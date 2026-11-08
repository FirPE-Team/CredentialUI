#ifndef UI_FRAME_H
#define UI_FRAME_H
#include <windows.h>

typedef struct UiFrame {
    UINT dpi;
    int width, height, padding, layer_width, layer_height;
    BOOL rounded, shadow, dark;
    HDC content_dc, layer_dc;
    HBITMAP content_bitmap, layer_bitmap;
    HGDIOBJ old_content, old_layer;
    DWORD *content_bits, *layer_bits;
    BYTE *coverage, *border, *shadow_alpha;
} UiFrame;

typedef void (*UiFramePaint)(void *context, HDC dc);
void ui_frame_init(UiFrame *frame);
void ui_frame_dispose(UiFrame *frame);
BOOL ui_frame_configure(UiFrame *frame, UINT dpi, int width, int height);
BOOL ui_frame_render(UiFrame *frame, HWND window, UiFramePaint paint, void *context);
BOOL ui_frame_contains(const UiFrame *frame, int x, int y);
#endif
