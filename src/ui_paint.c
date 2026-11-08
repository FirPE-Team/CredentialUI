#include "ui_paint.h"

int ui_px(UINT dpi, int value)
{
    return MulDiv(value, (int)dpi, 96);
}

RECT ui_rect(UINT dpi, int x, int y, int width, int height)
{
    RECT rect = {ui_px(dpi, x), ui_px(dpi, y),
                 ui_px(dpi, x + width), ui_px(dpi, y + height)};
    return rect;
}

void ui_fill(HDC dc, const RECT *rect, COLORREF color)
{
    HBRUSH brush = CreateSolidBrush(color);
    FillRect(dc, rect, brush);
    DeleteObject(brush);
}

static void round_shape(HDC dc, int width, int height, int radius,
                        COLORREF fill, COLORREF border, int line)
{
    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, line > 0 ? line : 1,
                        line > 0 ? border : fill);
    HGDIOBJ old_brush = SelectObject(dc, brush);
    HGDIOBJ old_pen = SelectObject(dc, pen);
    int inset = line / 2;
    RoundRect(dc, inset, inset, width - inset, height - inset,
              radius * 2, radius * 2);
    SelectObject(dc, old_pen);
    SelectObject(dc, old_brush);
    DeleteObject(pen);
    DeleteObject(brush);
}

/* Supersample shapes only: text remains native ClearType at the monitor DPI. */
void ui_round_rect(HDC dc, const RECT *rect, int radius,
                   COLORREF fill, COLORREF border, int border_width)
{
    const int samples = 4;
    int width = rect->right - rect->left;
    int height = rect->bottom - rect->top;
    HDC memory = CreateCompatibleDC(dc);
    HBITMAP bitmap = CreateCompatibleBitmap(dc, width * samples, height * samples);
    HGDIOBJ old_bitmap;
    RECT canvas = {0, 0, width * samples, height * samples};
    if (!memory || !bitmap) {
        if (bitmap) DeleteObject(bitmap);
        if (memory) DeleteDC(memory);
        ui_fill(dc, rect, fill);
        return;
    }
    old_bitmap = SelectObject(memory, bitmap);
    ui_fill(memory, &canvas, UI_BACKGROUND);
    round_shape(memory, width * samples, height * samples,
                radius * samples, fill, border, border_width * samples);
    {
        int old_mode = SetStretchBltMode(dc, HALFTONE);
        POINT old_origin;
        SetBrushOrgEx(dc, 0, 0, &old_origin);
        StretchBlt(dc, rect->left, rect->top, width, height,
                   memory, 0, 0, width * samples, height * samples, SRCCOPY);
        SetBrushOrgEx(dc, old_origin.x, old_origin.y, NULL);
        SetStretchBltMode(dc, old_mode);
    }
    SelectObject(memory, old_bitmap);
    DeleteObject(bitmap);
    DeleteDC(memory);
}

void ui_text(HDC dc, HFONT font, COLORREF color, const wchar_t *text,
             RECT rect, UINT flags)
{
    HGDIOBJ old_font = SelectObject(dc, font);
    int old_mode = SetBkMode(dc, TRANSPARENT);
    COLORREF old_color = SetTextColor(dc, color);
    DrawTextW(dc, text, -1, &rect, flags | DT_NOPREFIX | DT_SINGLELINE);
    SetTextColor(dc, old_color);
    SetBkMode(dc, old_mode);
    SelectObject(dc, old_font);
}

void ui_shield(HDC dc, UINT dpi, int x, int y)
{
    POINT points[8];
    const int shape[8][2] = {{7, 0}, {15, 3}, {15, 8}, {12, 12},
                              {7, 16}, {2, 12}, {0, 8}, {0, 3}};
    HBRUSH brush = CreateSolidBrush(UI_TEXT);
    HPEN pen = CreatePen(PS_SOLID, 1, UI_TEXT);
    HGDIOBJ old_brush = SelectObject(dc, brush);
    HGDIOBJ old_pen = SelectObject(dc, pen);
    int index;
    for (index = 0; index < 8; ++index) {
        points[index].x = ui_px(dpi, x + shape[index][0]);
        points[index].y = ui_px(dpi, y + shape[index][1]);
    }
    Polygon(dc, points, 8);
    SelectObject(dc, old_pen);
    SelectObject(dc, old_brush);
    DeleteObject(pen);
    DeleteObject(brush);
    {
        RECT vertical = ui_rect(dpi, x + 7, y, 1, 16);
        RECT horizontal = ui_rect(dpi, x, y + 6, 16, 1);
        ui_fill(dc, &vertical, UI_BACKGROUND);
        ui_fill(dc, &horizontal, UI_BACKGROUND);
    }
}

/* Small vector details are sampled directly into a DIB. This keeps one-pixel
 * borders and diagonal strokes symmetric, including fractional monitor scales. */
typedef COLORREF (*SampleColor)(double x, double y, const void *context);

static void sample_bitmap(HDC dc, int left, int top, int width, int height,
                           double logical_width, double logical_height,
                           SampleColor sample, const void *context)
{
    const unsigned int samples = 8;
    BITMAPINFO info = {0};
    HANDLE heap = GetProcessHeap();
    DWORD *pixels;
    int x, y;
    if (width <= 0 || height <= 0) return;
    pixels = HeapAlloc(heap, 0, (size_t)width * (size_t)height * sizeof(*pixels));
    if (!pixels) return;
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = width;
    info.bmiHeader.biHeight = -height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    for (y = 0; y < height; ++y) {
        for (x = 0; x < width; ++x) {
            unsigned int sx, sy, red = 0, green = 0, blue = 0;
            for (sy = 0; sy < samples; ++sy) {
                for (sx = 0; sx < samples; ++sx) {
                    double px = ((double)x + ((double)sx + 0.5) / samples) * logical_width / width;
                    double py = ((double)y + ((double)sy + 0.5) / samples) * logical_height / height;
                    COLORREF color = sample(px, py, context);
                    red += GetRValue(color);
                    green += GetGValue(color);
                    blue += GetBValue(color);
                }
            }
            red = (red + 32u) / 64u;
            green = (green + 32u) / 64u;
            blue = (blue + 32u) / 64u;
            pixels[(size_t)y * (size_t)width + (size_t)x] =
                (DWORD)((red << 16) | (green << 8) | blue);
        }
    }
    SetDIBitsToDevice(dc, left, top, (DWORD)width, (DWORD)height, 0, 0, 0,
                      (UINT)height, pixels, &info, DIB_RGB_COLORS);
    HeapFree(heap, 0, pixels);
}

static BOOL stroke_contains(double x, double y, double ax, double ay,
                             double bx, double by, double width, BOOL round_caps)
{
    double dx = bx - ax, dy = by - ay;
    double projection = ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy);
    if (!round_caps && (projection < 0.0 || projection > 1.0)) return FALSE;
    if (projection < 0.0) projection = 0.0;
    if (projection > 1.0) projection = 1.0;
    dx = x - (ax + projection * dx);
    dy = y - (ay + projection * dy);
    return dx * dx + dy * dy <= width * width * 0.25;
}

typedef struct CloseColors {
    COLORREF background, foreground;
} CloseColors;

static COLORREF close_sample(double x, double y, const void *context)
{
    const CloseColors *colors = context;
    BOOL covered = stroke_contains(x, y, 1.5, 1.5, 10.5, 10.5, 1.1, FALSE) ||
                   stroke_contains(x, y, 10.5, 1.5, 1.5, 10.5, 1.1, FALSE);
    return covered ? colors->foreground : colors->background;
}

void ui_close_glyph(HDC dc, UINT dpi, const RECT *button,
                     COLORREF background, COLORREF color)
{
    CloseColors colors = {background, color};
    int size = ui_px(dpi, 12);
    sample_bitmap(dc, (button->left + button->right - size) / 2,
                   (button->top + button->bottom - size) / 2,
                   size, size, 12.0, 12.0, close_sample, &colors);
}

static BOOL rounded_contains(double x, double y, double inset,
                              double size, double radius)
{
    double edge = inset + size;
    double corner_start = inset + radius, corner_end = edge - radius;
    double dx, dy;
    if (x < inset || y < inset || x >= edge || y >= edge) return FALSE;
    if ((x >= corner_start && x <= corner_end) || (y >= corner_start && y <= corner_end)) return TRUE;
    dx = x - (x < corner_start ? corner_start : corner_end);
    dy = y - (y < corner_start ? corner_start : corner_end);
    return dx * dx + dy * dy <= radius * radius;
}

typedef struct CheckboxStyle {
    BOOL checked, focused;
    COLORREF fill, border, tick;
} CheckboxStyle;

static COLORREF checkbox_sample(double x, double y, const void *context)
{
    const CheckboxStyle *style = context;
    COLORREF color = UI_BACKGROUND;
    if (style->focused && rounded_contains(x, y, 0.0, 24.0, 0.0) &&
        !rounded_contains(x, y, 1.0, 22.0, 0.0)) color = RGB(0, 120, 215);
    if (rounded_contains(x, y, 2.0, 20.0, 0.0)) {
        color = rounded_contains(x, y, 3.0, 18.0, 0.0) ? style->fill : style->border;
        if (style->checked &&
            (stroke_contains(x, y, 5.5, 12.5, 9.5, 16.5, 1.35, TRUE) ||
             stroke_contains(x, y, 9.5, 16.5, 18.5, 7.5, 1.35, TRUE)))
            color = style->tick;
    }
    return color;
}

/* A 24 px drawing area keeps a one-pixel keyboard focus ring clear of the
 * original 20 px checkbox. The box and label retain their original positions. */
void ui_checkbox(HDC dc, UINT dpi, BOOL checked, BOOL hover, BOOL pressed, BOOL focused)
{
    CheckboxStyle style;
    style.checked = checked;
    style.focused = focused;
    style.tick = RGB(255, 255, 255);
    if (checked) {
        style.fill = pressed ? RGB(0, 69, 120) :
                     (hover ? RGB(0, 90, 158) : RGB(0, 120, 215));
        style.border = style.fill;
    } else {
        style.fill = pressed ? RGB(204, 228, 247) :
                     (hover ? RGB(229, 241, 251) : UI_BACKGROUND);
        style.border = hover || pressed ? RGB(0, 120, 215) : RGB(118, 118, 118);
    }
    sample_bitmap(dc, 0, 0, ui_px(dpi, 24), ui_px(dpi, 24),
                   24.0, 24.0, checkbox_sample, &style);
}
