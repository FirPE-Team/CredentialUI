#ifndef UI_PAINT_H
#define UI_PAINT_H

#include <windows.h>

#define UI_BACKGROUND RGB(255, 255, 255)
#define UI_TEXT RGB(0, 0, 0)
#define UI_ACCENT RGB(0, 103, 192)
#define UI_MUTED RGB(137, 137, 137)

int ui_px(UINT dpi, int value);
RECT ui_rect(UINT dpi, int x, int y, int width, int height);
void ui_fill(HDC dc, const RECT *rect, COLORREF color);
void ui_round_rect(HDC dc, const RECT *rect, int radius,
                   COLORREF fill, COLORREF border, int border_width);
void ui_text(HDC dc, HFONT font, COLORREF color, const wchar_t *text,
             RECT rect, UINT flags);
void ui_shield(HDC dc, UINT dpi, int x, int y);
void ui_close_glyph(HDC dc, UINT dpi, const RECT *button, COLORREF background, COLORREF color);
void ui_checkbox(HDC dc, UINT dpi, BOOL checked, BOOL hover, BOOL pressed, BOOL focused);

#endif
