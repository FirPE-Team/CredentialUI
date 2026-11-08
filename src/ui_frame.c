#define WIN32_LEAN_AND_MEAN
#include "ui_frame.h"
#include "ui_paint.h"

/* Match OpenWith-for-WinPE: 16 px G2 corners, 1 px border, 32 px shadow margin. */
static DWORD os_build(void)
{
    typedef LONG (WINAPI *VersionFn)(OSVERSIONINFOW *);
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    VersionFn query = module ? (VersionFn)(void (*)(void))GetProcAddress(module, "RtlGetVersion") : NULL;
    OSVERSIONINFOW version = {0};
    version.dwOSVersionInfoSize = sizeof(version);
    return query && query(&version) == 0 ? version.dwBuildNumber : 0;
}

static BOOL shadow_enabled(void)
{
    BOOL enabled = TRUE;
    SystemParametersInfoW(SPI_GETDROPSHADOW, 0, &enabled, 0);
    return enabled;
}

static BOOL dark_theme(void)
{
    DWORD light = 1, bytes = sizeof(light);
    RegGetValueW(HKEY_CURRENT_USER,
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                 L"AppsUseLightTheme", RRF_RT_REG_DWORD, NULL, &light, &bytes);
    return light == 0;
}

/* Four-by-four coverage of x^4 + y^4 <= r^4, the reference's G2 curve. */
static BYTE coverage_at(int x, int y, int width, int height, int radius)
{
    int row, column, hits = 0;
    unsigned long long r = (unsigned long long)radius * 8u;
    unsigned long long r2 = r * r, r4 = r2 * r2;
    if (x < 0 || y < 0 || x >= width || y >= height) return 0;
    if (radius <= 0 || (x >= radius && x < width - radius) ||
        (y >= radius && y < height - radius)) return 255;
    for (row = 0; row < 4; ++row) {
        for (column = 0; column < 4; ++column) {
            long long dx = (long long)x * 8 + column * 2 + 1 -
                           (long long)(x < radius ? radius : width - radius) * 8;
            long long dy = (long long)y * 8 + row * 2 + 1 -
                           (long long)(y < radius ? radius : height - radius) * 8;
            unsigned long long dx2 = (unsigned long long)(dx * dx);
            unsigned long long dy2 = (unsigned long long)(dy * dy);
            if (dx2 * dx2 + dy2 * dy2 <= r4) ++hits;
        }
    }
    return (BYTE)((hits * 255 + 8) / 16);
}

/* Separable sliding box filter with clamped edges. Apply twice for soft shoulders. */
static void blur_axis(const BYTE *source, BYTE *target, int width, int height,
                       int radius, BOOL vertical)
{
    int line, position, k;
    int length = vertical ? height : width;
    int count = vertical ? width : height;
    size_t step = vertical ? (size_t)width : 1u;
    unsigned int span = (unsigned int)(radius * 2 + 1);
    for (line = 0; line < count; ++line) {
        size_t base = vertical ? (size_t)line : (size_t)line * (size_t)width;
        unsigned int sum = 0;
        for (k = -radius; k <= radius; ++k) {
            int sample = k < 0 ? 0 : (k >= length ? length - 1 : k);
            sum += source[base + (size_t)sample * step];
        }
        for (position = 0; position < length; ++position) {
            int remove = position - radius;
            int add = position + radius + 1;
            target[base + (size_t)position * step] = (BYTE)(sum / span);
            if (remove < 0) remove = 0;
            if (add >= length) add = length - 1;
            sum += source[base + (size_t)add * step];
            sum -= source[base + (size_t)remove * step];
        }
    }
}

static void blur(BYTE *image, BYTE *scratch, int width, int height, int radius)
{
    int pass;
    for (pass = 0; pass < 2; ++pass) {
        blur_axis(image, scratch, width, height, radius, FALSE);
        blur_axis(scratch, image, width, height, radius, TRUE);
    }
}

static BOOL create_surface(int width, int height, HDC *dc, HBITMAP *bitmap,
                            HGDIOBJ *old, DWORD **pixels)
{
    BITMAPINFO info = {0};
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = width;
    info.bmiHeader.biHeight = -height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    *dc = CreateCompatibleDC(NULL);
    *bitmap = CreateDIBSection(*dc, &info, DIB_RGB_COLORS, (void **)pixels, NULL, 0);
    if (!*dc || !*bitmap) return FALSE;
    *old = SelectObject(*dc, *bitmap);
    return TRUE;
}

void ui_frame_init(UiFrame *frame)
{
    ZeroMemory(frame, sizeof(*frame));
}

void ui_frame_dispose(UiFrame *frame)
{
    HANDLE heap = GetProcessHeap();
    if (frame->old_content) SelectObject(frame->content_dc, frame->old_content);
    if (frame->old_layer) SelectObject(frame->layer_dc, frame->old_layer);
    if (frame->content_bitmap) DeleteObject(frame->content_bitmap);
    if (frame->layer_bitmap) DeleteObject(frame->layer_bitmap);
    if (frame->content_dc) DeleteDC(frame->content_dc);
    if (frame->layer_dc) DeleteDC(frame->layer_dc);
    if (frame->coverage) HeapFree(heap, 0, frame->coverage);
    if (frame->border) HeapFree(heap, 0, frame->border);
    if (frame->shadow_alpha) HeapFree(heap, 0, frame->shadow_alpha);
    ui_frame_init(frame);
}

BOOL ui_frame_configure(UiFrame *frame, UINT dpi, int width, int height)
{
    HANDLE heap = GetProcessHeap();
    BOOL rounded = os_build() >= 22000;
    BOOL shadow = shadow_enabled();
    BOOL dark = dark_theme();
    size_t pixels, body_pixels;
    BYTE *ambient = NULL, *drop = NULL, *scratch = NULL;
    int x, y, radius, border_width;
    if (frame->content_dc && frame->dpi == dpi && frame->width == width &&
        frame->height == height && frame->rounded == rounded && frame->shadow == shadow) {
        frame->dark = dark;
        return TRUE;
    }
    ui_frame_dispose(frame);
    frame->dpi = dpi;
    frame->width = width;
    frame->height = height;
    frame->rounded = rounded;
    frame->shadow = shadow;
    frame->dark = dark;
    frame->padding = shadow ? ui_px(dpi, 32) : 0;
    frame->layer_width = width + frame->padding * 2;
    frame->layer_height = height + frame->padding * 2;
    pixels = (size_t)frame->layer_width * (size_t)frame->layer_height;
    body_pixels = (size_t)width * (size_t)height;
    frame->coverage = HeapAlloc(heap, 0, body_pixels);
    frame->border = HeapAlloc(heap, 0, body_pixels);
    frame->shadow_alpha = HeapAlloc(heap, HEAP_ZERO_MEMORY, pixels);
    if (!frame->coverage || !frame->border || !frame->shadow_alpha ||
        !create_surface(width, height, &frame->content_dc, &frame->content_bitmap,
                        &frame->old_content, &frame->content_bits) ||
        !create_surface(frame->layer_width, frame->layer_height, &frame->layer_dc,
                        &frame->layer_bitmap, &frame->old_layer, &frame->layer_bits)) goto failure;
    radius = rounded ? ui_px(dpi, 16) : 0;
    border_width = ui_px(dpi, 1);
    for (y = 0; y < height; ++y) {
        for (x = 0; x < width; ++x) {
            size_t index = (size_t)y * (size_t)width + (size_t)x;
            BYTE outer = coverage_at(x, y, width, height, radius);
            BYTE inner = coverage_at(x - border_width, y - border_width,
                                     width - border_width * 2, height - border_width * 2,
                                     rounded ? radius - border_width : 0);
            frame->coverage[index] = outer;
            frame->border[index] = (BYTE)(((unsigned int)outer * (255u - inner) + 127u) / 255u);
        }
    }
    if (!shadow) return TRUE;
    ambient = HeapAlloc(heap, HEAP_ZERO_MEMORY, pixels);
    drop = HeapAlloc(heap, HEAP_ZERO_MEMORY, pixels);
    scratch = HeapAlloc(heap, 0, pixels);
    if (!ambient || !drop || !scratch) goto failure;
    for (y = 0; y < height; ++y) {
        size_t row = (size_t)(y + frame->padding) * (size_t)frame->layer_width + (size_t)frame->padding;
        size_t drop_row = row + (size_t)ui_px(dpi, 4) * (size_t)frame->layer_width;
        for (x = 0; x < width; ++x) {
            BYTE value = frame->coverage[(size_t)y * (size_t)width + (size_t)x];
            ambient[row + (size_t)x] = value;
            drop[drop_row + (size_t)x] = value;
        }
    }
    blur(ambient, scratch, frame->layer_width, frame->layer_height, ui_px(dpi, 18));
    blur(drop, scratch, frame->layer_width, frame->layer_height, ui_px(dpi, 11));
    {
        size_t index;
        for (index = 0; index < pixels; ++index) {
            unsigned int alpha = ((unsigned int)ambient[index] * 26u + (unsigned int)drop[index] * 44u + 127u) / 255u;
            frame->shadow_alpha[index] = (BYTE)(alpha > 74u ? 74u : alpha);
        }
    }
    HeapFree(heap, 0, ambient);
    HeapFree(heap, 0, drop);
    HeapFree(heap, 0, scratch);
    return TRUE;
failure:
    if (ambient) HeapFree(heap, 0, ambient);
    if (drop) HeapFree(heap, 0, drop);
    if (scratch) HeapFree(heap, 0, scratch);
    ui_frame_dispose(frame);
    return FALSE;
}

BOOL ui_frame_contains(const UiFrame *frame, int x, int y)
{
    return x >= 0 && y >= 0 && x < frame->width && y < frame->height &&
           frame->coverage && frame->coverage[(size_t)y * (size_t)frame->width + (size_t)x] != 0;
}

BOOL ui_frame_render(UiFrame *frame, HWND window, UiFramePaint paint, void *context)
{
    size_t count = (size_t)frame->layer_width * (size_t)frame->layer_height;
    size_t index;
    int x, y;
    POINT destination, source = {0, 0};
    SIZE size = {frame->layer_width, frame->layer_height};
    BLENDFUNCTION blend = {AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};
    RECT bounds;
    unsigned int edge = frame->dark ? 82u : 173u;
    if (!frame->content_dc) return FALSE;
    paint(context, frame->content_dc);
    GdiFlush();
    for (index = 0; index < count; ++index)
        frame->layer_bits[index] = (DWORD)frame->shadow_alpha[index] << 24;
    for (y = 0; y < frame->height; ++y) {
        for (x = 0; x < frame->width; ++x) {
            size_t body = (size_t)y * (size_t)frame->width + (size_t)x;
            size_t target = (size_t)(y + frame->padding) * (size_t)frame->layer_width + (size_t)(x + frame->padding);
            unsigned int alpha = frame->coverage[body];
            unsigned int border_alpha = frame->border[body];
            unsigned int pixel = frame->content_bits[body];
            unsigned int red = (pixel >> 16) & 255u;
            unsigned int green = (pixel >> 8) & 255u;
            unsigned int blue = pixel & 255u;
            unsigned int out_alpha;
            if (!alpha) continue;
            if (frame->dark) border_alpha = (border_alpha * 190u + 127u) / 255u;
            red = (edge * border_alpha + red * (255u - border_alpha) + 127u) / 255u;
            green = (edge * border_alpha + green * (255u - border_alpha) + 127u) / 255u;
            blue = (edge * border_alpha + blue * (255u - border_alpha) + 127u) / 255u;
            out_alpha = alpha + ((unsigned int)frame->shadow_alpha[target] * (255u - alpha) + 127u) / 255u;
            frame->layer_bits[target] = (DWORD)((out_alpha << 24) |
                (((red * alpha + 127u) / 255u) << 16) |
                (((green * alpha + 127u) / 255u) << 8) |
                ((blue * alpha + 127u) / 255u));
        }
    }
    GetWindowRect(window, &bounds);
    destination.x = bounds.left;
    destination.y = bounds.top;
    return UpdateLayeredWindow(window, NULL, &destination, &size, frame->layer_dc,
                                &source, 0, &blend, ULW_ALPHA);
}
