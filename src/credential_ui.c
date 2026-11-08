#define WIN32_LEAN_AND_MEAN
#include "credential_ui.h"
#include "ui_paint.h"
#include "ui_frame.h"
#include "resource.h"
#include <commctrl.h>
#include <windowsx.h>
#include <wchar.h>
#include <stdio.h>

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

#define WINDOW_WIDTH 451
#define WINDOW_HEIGHT 416
#define CLOSE_BUTTON_SIZE 30
#define CLOSE_BUTTON_LEFT (WINDOW_WIDTH - CLOSE_BUTTON_SIZE)
#define ID_USERNAME 1001
#define ID_PASSWORD 1002
#define ID_REMEMBER 1003
#define ID_CLOSE 1004
#define WM_UI_STATUS (WM_APP + 1)
#define WM_UI_RENDER (WM_APP + 2)
#define ID_CARET_TIMER 1

static const wchar_t WINDOW_CLASS[] = L"CredentialUI.Window";

typedef struct UiState {
    const CredentialUiRequest *request;
    CredentialUiResult *result;
    HINSTANCE instance;
    HWND window;
    HWND username;
    HWND password;
    HWND remember;
    HWND confirm;
    HWND cancel;
    HWND close;
    HWND last_focus;
    HFONT body_font;
    HFONT title_font;
    HFONT heading_font;
    HICON title_icon;
    UINT dpi;
    UiFrame frame;
    BOOL render_pending;
    BOOL rendering;
    BOOL caret_visible;
    DWORD caret_epoch;
    wchar_t status[256];
} UiState;

static LRESULT CALLBACK window_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK edit_proc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
static LRESULT CALLBACK button_proc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);

/* Optional APIs are resolved at runtime so the same executable works in WinPE. */
static UINT window_dpi(HWND window)
{
    typedef UINT (WINAPI *GetDpiFn)(HWND);
    HMODULE user = GetModuleHandleW(L"user32.dll");
    GetDpiFn get_dpi = (GetDpiFn)(void (*)(void))GetProcAddress(user, "GetDpiForWindow");
    HDC dc;
    UINT dpi;
    if (get_dpi && window) return get_dpi(window);
    dc = GetDC(NULL);
    dpi = dc ? (UINT)GetDeviceCaps(dc, LOGPIXELSX) : 96;
    if (dc) ReleaseDC(NULL, dc);
    return dpi ? dpi : 96;
}

static void enable_dpi_awareness(void)
{
    typedef BOOL (WINAPI *SetContextFn)(HANDLE);
    typedef HRESULT (WINAPI *SetAwarenessFn)(int);
    HMODULE user = GetModuleHandleW(L"user32.dll");
    SetContextFn set_context =
        (SetContextFn)(void (*)(void))GetProcAddress(user, "SetProcessDpiAwarenessContext");
    HMODULE shcore;
    if (set_context && set_context((HANDLE)(INT_PTR)-4)) return;
    shcore = LoadLibraryW(L"shcore.dll");
    if (shcore) {
        SetAwarenessFn set_awareness =
            (SetAwarenessFn)(void (*)(void))GetProcAddress(shcore, "SetProcessDpiAwareness");
        HRESULT result = set_awareness ? set_awareness(2) : E_NOTIMPL;
        FreeLibrary(shcore);
        if (SUCCEEDED(result) || result == E_ACCESSDENIED) return;
    }
    SetProcessDPIAware();
}

static void request_render(UiState *ui)
{
    if (!ui->render_pending && IsWindow(ui->window)) {
        ui->render_pending = TRUE;
        PostMessageW(ui->window, WM_UI_RENDER, 0, 0);
    }
}

static HFONT create_font(UINT dpi, int height, int weight, const wchar_t *family)
{
    return CreateFontW(-ui_px(dpi, height), 0, 0, 0, weight, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, DEFAULT_PITCH, family);
}

static void set_dpi_resources(UiState *ui)
{
    HFONT old_body = ui->body_font;
    HFONT old_title = ui->title_font;
    HFONT old_heading = ui->heading_font;
    HICON old_icon = ui->title_icon;
    HWND controls[] = {ui->username, ui->password, ui->remember,
                       ui->confirm, ui->cancel, ui->close};
    size_t index;
    ui->body_font = create_font(ui->dpi, 14, FW_NORMAL, L"Microsoft YaHei UI");
    ui->title_font = create_font(ui->dpi, 12, FW_NORMAL, L"Segoe UI");
    ui->heading_font = create_font(ui->dpi, 20, FW_BOLD, L"Microsoft YaHei UI");
    ui->title_icon = (HICON)LoadImageW(ui->instance, MAKEINTRESOURCEW(IDI_APP),
                                     IMAGE_ICON, ui_px(ui->dpi, 16),
                                     ui_px(ui->dpi, 16), LR_DEFAULTCOLOR);
    for (index = 0; index < sizeof(controls) / sizeof(controls[0]); ++index) {
        if (controls[index])
            SendMessageW(controls[index], WM_SETFONT, (WPARAM)ui->body_font, TRUE);
    }
    if (old_body) DeleteObject(old_body);
    if (old_title) DeleteObject(old_title);
    if (old_heading) DeleteObject(old_heading);
    if (old_icon) DestroyIcon(old_icon);
}

static void position_control(UiState *ui, HWND control,
                             int x, int y, int width, int height)
{
    if (control) SetWindowPos(control, NULL, ui->frame.padding + ui_px(ui->dpi, x),
                             ui->frame.padding + ui_px(ui->dpi, y),
                             ui_px(ui->dpi, width), ui_px(ui->dpi, height),
                             SWP_NOZORDER | SWP_NOACTIVATE);
}

static void layout_controls(UiState *ui)
{
    position_control(ui, ui->username, 29, 165, 329, 21);
    position_control(ui, ui->password, 29, 228, 329, 21);
    position_control(ui, ui->remember, 19, 269, 202, 24);
    position_control(ui, ui->confirm, 21, 360, 201, 32);
    position_control(ui, ui->cancel, 226, 360, 201, 32);
    position_control(ui, ui->close, CLOSE_BUTTON_LEFT, 0, CLOSE_BUTTON_SIZE, CLOSE_BUTTON_SIZE);
}

static HWND create_control(UiState *ui, const wchar_t *class_name,
                            const wchar_t *text, DWORD style, int identifier)
{
    return CreateWindowExW(0, class_name, text, WS_CHILD | WS_VISIBLE | style,
                           0, 0, 0, 0, ui->window,
                           (HMENU)(INT_PTR)identifier, ui->instance, NULL);
}

static BOOL create_controls(UiState *ui)
{
    HWND buttons[4];
    size_t index;
    /* Native EDIT controls retain IME, selection, clipboard and password masking. */
    ui->username = create_control(ui, L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL,
                                  ID_USERNAME);
    ui->password = create_control(ui, L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL |
                                  ES_PASSWORD, ID_PASSWORD);
    ui->remember = create_control(ui, L"BUTTON", L"记住我的凭据",
                                  WS_TABSTOP | BS_AUTOCHECKBOX, ID_REMEMBER);
    ui->confirm = create_control(ui, L"BUTTON", L"确定",
                                 WS_TABSTOP | BS_DEFPUSHBUTTON, IDOK);
    ui->cancel = create_control(ui, L"BUTTON", L"取消",
                                WS_TABSTOP | BS_PUSHBUTTON, IDCANCEL);
    ui->close = create_control(ui, L"BUTTON", L"关闭", BS_PUSHBUTTON, ID_CLOSE);
    if (!ui->username || !ui->password || !ui->remember ||
        !ui->confirm || !ui->cancel || !ui->close) return FALSE;
    if (!SetWindowSubclass(ui->username, edit_proc, 1, (DWORD_PTR)ui) ||
        !SetWindowSubclass(ui->password, edit_proc, 1, (DWORD_PTR)ui)) return FALSE;
    buttons[0] = ui->remember;
    buttons[1] = ui->confirm;
    buttons[2] = ui->cancel;
    buttons[3] = ui->close;
    for (index = 0; index < 4; ++index) {
        if (!SetWindowSubclass(buttons[index], button_proc, 1, (DWORD_PTR)ui))
            return FALSE;
    }
    SendMessageW(ui->username, EM_SETLIMITTEXT, 32767, 0);
    SendMessageW(ui->password, EM_SETLIMITTEXT, 256, 0);
    /* Use the larger filled circle while retaining native password editing. */
    SendMessageW(ui->password, EM_SETPASSWORDCHAR, 0x25CF, 0);
    set_dpi_resources(ui);
    layout_controls(ui);
    return TRUE;
}

static void paint_field(UiState *ui, HDC dc, HWND edit, int top)
{
    RECT rect = ui_rect(ui->dpi, 21, top, 346, 32);
    BOOL focused = GetFocus() == edit;
    /* Use the same 1 logical pixel outline in resting and focused states. */
    COLORREF border = focused ? RGB(0, 120, 215) : RGB(153, 153, 153);
    ui_round_rect(dc, &rect, ui_px(ui->dpi, 4), UI_BACKGROUND,
                  border, ui_px(ui->dpi, 1));
}

static void paint_window(UiState *ui, HDC dc)
{
    RECT client;
    client = ui_rect(ui->dpi, 0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
    ui_fill(dc, &client, UI_BACKGROUND);
    if (ui->title_icon)
        DrawIconEx(dc, ui_px(ui->dpi, 21), ui_px(ui->dpi, 12), ui->title_icon,
                   ui_px(ui->dpi, 16), ui_px(ui->dpi, 16), 0, NULL, DI_NORMAL);
    ui_text(dc, ui->title_font, UI_TEXT, L"Windows 安全中心",
            ui_rect(ui->dpi, 61, 9, 300, 22), DT_LEFT | DT_VCENTER);
    ui_text(dc, ui->heading_font, UI_TEXT, ui->request && ui->request->caption[0] ? ui->request->caption : L"输入网络凭据",
            ui_rect(ui->dpi, 21, 51, 360, 30), DT_LEFT | DT_VCENTER);
    wchar_t prompt[CREDENTIAL_TEXT_CAP];
    if(ui->request && ui->request->target[0]) {
        _snwprintf_s(prompt,CREDENTIAL_TEXT_CAP,_TRUNCATE,L"输入你的凭据以连接到: %s",ui->request->target);
    } else lstrcpyW(prompt,L"输入你的凭据以连接到:");
    ui_text(dc, ui->body_font, UI_TEXT, prompt,
            ui_rect(ui->dpi, 21, 91, 380, 22), DT_LEFT | DT_VCENTER);
    ui_text(dc, ui->body_font, UI_TEXT, L"用户名",
            ui_rect(ui->dpi, 21, 138, 346, 20), DT_LEFT | DT_VCENTER);
    ui_text(dc, ui->body_font, UI_TEXT, L"密码",
            ui_rect(ui->dpi, 21, 201, 346, 20), DT_LEFT | DT_VCENTER);
    paint_field(ui, dc, ui->username, 158);
    paint_field(ui, dc, ui->password, 221);
    if (ui->status[0]) {
        ui_text(dc, ui->body_font, RGB(255, 0, 0), ui->status,
                ui_rect(ui->dpi, 21, 321, 406, 22), DT_LEFT | DT_VCENTER);
    }
}

static void paint_placeholder(UiState *ui, HWND edit, HDC dc)
{
    if (GetWindowTextLengthW(edit) == 0) {
        RECT rect;
        GetClientRect(edit, &rect);
        ui_text(dc, ui->body_font, UI_MUTED,
                edit == ui->username ? L"用户名" : L"密码", rect, DT_LEFT | DT_TOP);
    }
}

static LRESULT CALLBACK edit_proc(HWND edit, UINT message, WPARAM wparam,
                                  LPARAM lparam, UINT_PTR identifier,
                                  DWORD_PTR reference)
{
    UiState *ui = (UiState *)reference;
    LRESULT result;
    if (message == WM_SETFOCUS) ui->last_focus = edit;
    if (message == WM_SETFOCUS || message == WM_KEYDOWN || message == WM_LBUTTONDOWN ||
        message == WM_CHAR || message == WM_IME_COMPOSITION) {
        ui->caret_epoch = GetTickCount();
        ui->caret_visible = TRUE;
    }
    if (message == WM_KEYDOWN && wparam == 'A' && GetKeyState(VK_CONTROL) < 0) {
        SendMessageW(edit, EM_SETSEL, 0, -1);
        request_render(ui);
        return 0;
    }
    if (message == WM_NCDESTROY) {
        RemoveWindowSubclass(edit, edit_proc, identifier);
        return DefSubclassProc(edit, message, wparam, lparam);
    }
    result = DefSubclassProc(edit, message, wparam, lparam);
    if (message == WM_PAINT) {
        HDC dc = GetDC(edit);
        if (dc) {
            paint_placeholder(ui, edit, dc);
            ReleaseDC(edit, dc);
        }
    } else if (message == WM_PRINTCLIENT && wparam) {
        paint_placeholder(ui, edit, (HDC)wparam);
    } else if (message == WM_SETFOCUS || message == WM_KILLFOCUS) {
        RECT rect = ui_rect(ui->dpi, 21, edit == ui->username ? 158 : 221, 346, 32);
        InvalidateRect(ui->window, &rect, FALSE);
        InvalidateRect(edit, NULL, FALSE);
    } else if (message == WM_SETTEXT || message == WM_CHAR || message == WM_CUT ||
               message == WM_PASTE || message == WM_CLEAR || message == WM_UNDO) {
        InvalidateRect(edit, NULL, FALSE);
    }
    if (message == WM_PAINT || message == WM_SETTEXT || message == WM_CHAR ||
        message == WM_KEYDOWN || message == WM_KEYUP || message == WM_SETFOCUS ||
        message == WM_KILLFOCUS || message == WM_CUT || message == WM_PASTE ||
        message == WM_CLEAR || message == WM_UNDO || message == EM_SETSEL ||
        message == WM_LBUTTONDOWN || message == WM_LBUTTONUP ||
        message == WM_IME_COMPOSITION ||
        (message == WM_MOUSEMOVE && (wparam & MK_LBUTTON))) request_render(ui);
    return result;
}

static BOOL mouse_over(HWND control)
{
    POINT point;
    RECT rect;
    GetCursorPos(&point);
    ScreenToClient(control, &point);
    GetClientRect(control, &rect);
    return PtInRect(&rect, point);
}

static void paint_button(UiState *ui, HWND button, HDC dc)
{
    RECT rect;
    BOOL hover = mouse_over(button);
    BOOL down = (SendMessageW(button, BM_GETSTATE, 0, 0) & BST_PUSHED) != 0;
    int identifier = GetDlgCtrlID(button);
    BOOL focus = GetFocus() == button &&
                 !(SendMessageW(ui->window, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS);
    GetClientRect(button, &rect);
    ui_fill(dc, &rect, UI_BACKGROUND);
    if (identifier == ID_CLOSE) {
        COLORREF background = down ? RGB(196, 43, 28) :
                              (hover ? RGB(232, 17, 35) : UI_BACKGROUND);
        ui_fill(dc, &rect, background);
        ui_close_glyph(dc, ui->dpi, &rect, background,
                        hover || down ? RGB(255, 255, 255) : RGB(32, 32, 32));
    } else if (identifier == ID_REMEMBER) {
        RECT label = rect;
        BOOL checked = SendMessageW(button, BM_GETCHECK, 0, 0) == BST_CHECKED;
        ui_checkbox(dc, ui->dpi, checked, hover, down, focus);
        label.left = ui_px(ui->dpi, 30);
        ui_text(dc, ui->body_font, UI_TEXT, L"记住我的凭据", label, DT_LEFT | DT_VCENTER);
    } else {
        BOOL primary = identifier == IDOK;
        COLORREF fill = primary ? UI_ACCENT : RGB(238, 238, 238);
        COLORREF border = primary ? UI_ACCENT : RGB(232, 232, 232);
        RECT underline = rect;
        int saved;
        COLORREF text = primary ? RGB(255, 255, 255) : UI_TEXT;
        int border_width = 1;
        if (hover || down) {
            fill = down ? RGB(185, 185, 185) : RGB(205, 205, 205);
            border = RGB(128, 128, 128);
            text = UI_TEXT;
            border_width = 2;
        }
        ui_round_rect(dc, &rect, ui_px(ui->dpi, 4), fill, border, ui_px(ui->dpi, border_width));
        if (!primary && !hover && !down) {
            saved = SaveDC(dc);
            IntersectClipRect(dc, ui_px(ui->dpi, 4), rect.bottom - ui_px(ui->dpi, 1),
                              rect.right - ui_px(ui->dpi, 4), rect.bottom);
            ui_fill(dc, &underline, RGB(205, 205, 205));
            RestoreDC(dc, saved);
        }
        ui_text(dc, ui->body_font, text, primary ? L"确定" : L"取消",
                rect, DT_CENTER | DT_VCENTER);
        if (focus) {
            InflateRect(&rect, -ui_px(ui->dpi, 3), -ui_px(ui->dpi, 3));
            SetTextColor(dc, text);
            DrawFocusRect(dc, &rect);
        }
    }
}

static LRESULT CALLBACK button_proc(HWND button, UINT message, WPARAM wparam,
                                    LPARAM lparam, UINT_PTR identifier,
                                    DWORD_PTR reference)
{
    UiState *ui = (UiState *)reference;
    LRESULT result;
    if (message == WM_SETFOCUS) ui->last_focus = button;
    if (message == WM_PAINT || message == WM_PRINTCLIENT) {
        PAINTSTRUCT ps;
        HDC dc = message == WM_PAINT ? BeginPaint(button, &ps) : (HDC)wparam;
        if (dc) paint_button(ui, button, dc);
        if (message == WM_PAINT) {
            EndPaint(button, &ps);
            request_render(ui);
        }
        return 0;
    }
    if (message == WM_ERASEBKGND) return 1;
    if (message == WM_NCDESTROY) {
        RemoveWindowSubclass(button, button_proc, identifier);
        return DefSubclassProc(button, message, wparam, lparam);
    }
    if (message == WM_MOUSEMOVE) {
        TRACKMOUSEEVENT tracking = {sizeof(tracking), TME_LEAVE, button, 0};
        TrackMouseEvent(&tracking);
    }
    result = DefSubclassProc(button, message, wparam, lparam);
    if (message == WM_MOUSEMOVE || message == WM_MOUSELEAVE ||
        message == WM_LBUTTONDOWN || message == WM_LBUTTONUP ||
        message == WM_KEYDOWN || message == WM_KEYUP || message == WM_ENABLE ||
        message == WM_SETFOCUS || message == WM_KILLFOCUS ||
        message == BM_SETCHECK || message == BM_SETSTATE || message == WM_UPDATEUISTATE)
    {
        InvalidateRect(button, NULL, FALSE);
        request_render(ui);
    }
    return result;
}

/* Native controls keep their input/IME/accessibility behavior. Their client areas
 * are composed into the same DIB as the frame for UpdateLayeredWindow. */
static void paint_composite(void *context, HDC dc)
{
    UiState *ui = context;
    HWND controls[] = {ui->username, ui->password, ui->remember,
                       ui->confirm, ui->cancel, ui->close};
    size_t index;
    paint_window(ui, dc);
    for (index = 0; index < sizeof(controls) / sizeof(controls[0]); ++index) {
        HWND control = controls[index];
        RECT rect;
        POINT origin;
        int saved;
        GetWindowRect(control, &rect);
        origin.x = rect.left;
        origin.y = rect.top;
        ScreenToClient(ui->window, &origin);
        origin.x -= ui->frame.padding;
        origin.y -= ui->frame.padding;
        saved = SaveDC(dc);
        SetViewportOrgEx(dc, origin.x, origin.y, NULL);
        IntersectClipRect(dc, 0, 0, rect.right - rect.left, rect.bottom - rect.top);
        if (control == ui->username || control == ui->password) {
            RECT background = {0, 0, rect.right - rect.left, rect.bottom - rect.top};
            ui_fill(dc, &background, UI_BACKGROUND);
            SendMessageW(control, WM_PRINTCLIENT, (WPARAM)dc, PRF_CLIENT | PRF_ERASEBKGND);
            if (GetFocus() == control && GetForegroundWindow() == ui->window && ui->caret_visible) {
                GUITHREADINFO info = {0};
                info.cbSize = sizeof(info);
                if (GetGUIThreadInfo(GetCurrentThreadId(), &info) && info.hwndCaret == control) {
                    DWORD first = 0, last = 0;
                    SendMessageW(control, EM_GETSEL, (WPARAM)&first, (LPARAM)&last);
                    if (first == last) ui_fill(dc, &info.rcCaret, UI_TEXT);
                }
            }
        } else {
            paint_button(ui, control, dc);
        }
        RestoreDC(dc, saved);
    }
}

static BOOL render_window(UiState *ui)
{
    BOOL result;
    if (ui->rendering || !ui->frame.content_dc) return TRUE;
    ui->rendering = TRUE;
    result = ui_frame_render(&ui->frame, ui->window, paint_composite, ui);
    ui->rendering = FALSE;
    return result;
}

static BOOL refresh_frame(UiState *ui, const RECT *suggested)
{
    RECT previous;
    int old_padding = ui->frame.padding;
    int left, top;
    GetWindowRect(ui->window, &previous);
    left = suggested ? suggested->left : previous.left + old_padding;
    top = suggested ? suggested->top : previous.top + old_padding;
    if (!ui_frame_configure(&ui->frame, ui->dpi, ui_px(ui->dpi, WINDOW_WIDTH),
                             ui_px(ui->dpi, WINDOW_HEIGHT))) return FALSE;
    layout_controls(ui);
    if (!suggested) {
        left -= ui->frame.padding;
        top -= ui->frame.padding;
    }
    SetWindowPos(ui->window, NULL, left, top, ui->frame.layer_width, ui->frame.layer_height,
                  SWP_NOZORDER | SWP_NOACTIVATE);
    request_render(ui);
    return TRUE;
}

void credential_ui_set_status(HWND window, const wchar_t *text)
{
    SendMessageW(window, WM_UI_STATUS, 0, (LPARAM)text);
}

static LRESULT CALLBACK window_proc(HWND window, UINT message,
                                    WPARAM wparam, LPARAM lparam)
{
    UiState *ui = (UiState *)GetWindowLongPtrW(window, GWLP_USERDATA);
    if (message == WM_NCCREATE) {
        const CREATESTRUCTW *create = (const CREATESTRUCTW *)lparam;
        ui = (UiState *)create->lpCreateParams;
        ui->window = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, (LONG_PTR)ui);
    }
    /* No native non-client frame. Border, corners and shadow share one alpha layer. */
    if (message == WM_NCCALCSIZE) return 0;
    if (!ui) return DefWindowProcW(window, message, wparam, lparam);
    switch (message) {
    case WM_CREATE:
        ui->dpi = window_dpi(window);
        if (!ui_frame_configure(&ui->frame, ui->dpi, ui_px(ui->dpi, WINDOW_WIDTH),
                                 ui_px(ui->dpi, WINDOW_HEIGHT)) || !create_controls(ui)) return -1;
        ui->caret_epoch = GetTickCount();
        ui->caret_visible = TRUE;
        SetTimer(window, ID_CARET_TIMER, 50, NULL);
        return 0;
    case WM_NCHITTEST: {
        POINT point = {GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
        ScreenToClient(window, &point);
        point.x -= ui->frame.padding;
        point.y -= ui->frame.padding;
        if (!ui_frame_contains(&ui->frame, point.x, point.y)) return HTNOWHERE;
        if (point.y < ui_px(ui->dpi, 65) &&
            !(point.x >= ui_px(ui->dpi, CLOSE_BUTTON_LEFT) &&
              point.y < ui_px(ui->dpi, CLOSE_BUTTON_SIZE))) return HTCAPTION;
        return HTCLIENT;
    }
    case WM_NCLBUTTONDBLCLK:
        if (wparam == HTCAPTION) return 0;
        break;
    case WM_SYSCOMMAND:
        if ((wparam & 0xFFF0) == SC_MAXIMIZE || (wparam & 0xFFF0) == SC_SIZE) return 0;
        break;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        BeginPaint(window, &ps);
        EndPaint(window, &ps);
        request_render(ui);
        return 0;
    }
    case WM_UI_RENDER:
        ui->render_pending = FALSE;
        render_window(ui);
        return 0;
    case WM_TIMER:
        if(wparam==2 && ui->request) {
            DWORD stop=0;
            if(ui->request->deadline && GetTickCount64()>=ui->request->deadline)stop=ERROR_TIMEOUT;
            else if((ui->request->cancel && WaitForSingleObject(ui->request->cancel,0)==WAIT_OBJECT_0)||
              (ui->request->parent_process && WaitForSingleObject(ui->request->parent_process,0)==WAIT_OBJECT_0)||
              (ui->request->owner && !IsWindow(ui->request->owner)))stop=ERROR_CANCELLED;
            if(stop){ui->result->result=stop;SetWindowTextW(ui->password,L"");DestroyWindow(window);}
        }

        if (wparam == ID_CARET_TIMER) {
            HWND focus = GetFocus();
            if (focus == ui->username || focus == ui->password) {
                UINT blink = GetCaretBlinkTime();
                BOOL visible = blink == INFINITE || !blink ||
                    ((GetTickCount() - ui->caret_epoch) / blink) % 2u == 0;
                if (visible != ui->caret_visible) {
                    ui->caret_visible = visible;
                    request_render(ui);
                }
            }
            return 0;
        }
        break;
    case WM_PRINTCLIENT:
        if (wparam) paint_composite(ui, (HDC)wparam);
        return 0;
    case WM_CTLCOLOREDIT:
        SetBkColor((HDC)wparam, UI_BACKGROUND);
        SetTextColor((HDC)wparam, UI_TEXT);
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    case WM_COMMAND:
        request_render(ui);
        switch (LOWORD(wparam)) {
        case IDOK:
            if (!ui->result) return 0;
            if(GetWindowTextLengthW(ui->username)>=CREDENTIAL_USERNAME_CAP ||
               GetWindowTextLengthW(ui->password)>=CREDENTIAL_PASSWORD_CAP) {
                credential_ui_set_status(window,L"输入过长，用户名和密码最多 511 个 UTF-16 单元。");return 0;
            }
            if(!GetWindowTextW(ui->username,ui->result->username,CREDENTIAL_USERNAME_CAP)) {
                credential_ui_set_status(window,L"请输入用户名。");SetFocus(ui->username);return 0;
            }
            GetWindowTextW(ui->password,ui->result->password,CREDENTIAL_PASSWORD_CAP);
            ui->result->save=ui->request->allow_save && SendMessageW(ui->remember,BM_GETCHECK,0,0)==BST_CHECKED;
            ui->result->result=ERROR_SUCCESS;
            SetWindowTextW(ui->password,L"");DestroyWindow(window);return 0;
        case IDCANCEL:
        case ID_CLOSE:
            if (HIWORD(wparam) == BN_CLICKED) { SetWindowTextW(ui->password,L""); DestroyWindow(window); }
            return 0;
        case ID_REMEMBER:
            InvalidateRect(ui->remember, NULL, FALSE);
            return 0;
        }
        break;
    case WM_UI_STATUS: {
        lstrcpynW(ui->status, lparam ? (const wchar_t *)lparam : L"",
                   (int)(sizeof(ui->status) / sizeof(ui->status[0])));
        request_render(ui);
        return 0;
    }
    case WM_SETFOCUS:
        SetFocus(ui->last_focus && IsWindow(ui->last_focus)
                 ? ui->last_focus : ui->username);
        return 0;
    case WM_ACTIVATE:
        if (LOWORD(wparam) != WA_INACTIVE)
            SetFocus(ui->last_focus && IsWindow(ui->last_focus)
                     ? ui->last_focus : ui->username);
        request_render(ui);
        return 0;
    case WM_DPICHANGED: {
        const RECT *suggested = (const RECT *)lparam;
        ui->dpi = HIWORD(wparam);
        if (ui->dpi < 96 || ui->dpi > 768) ui->dpi = 96;
        set_dpi_resources(ui);
        if (!refresh_frame(ui, suggested)) DestroyWindow(window);
        return 0;
    }
    case WM_SETTINGCHANGE:
    case WM_THEMECHANGED:
    case WM_DWMCOMPOSITIONCHANGED:
        if (!refresh_frame(ui, NULL)) DestroyWindow(window);
        return 0;
    case WM_CLOSE:
        SetWindowTextW(ui->password,L"");
        DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        KillTimer(window, ID_CARET_TIMER);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

static int run_window(HINSTANCE instance, int show_command, const CredentialUiRequest *request, CredentialUiResult *response)
{
    UiState ui = {0};
    WNDCLASSEXW window_class = {0};
    INITCOMMONCONTROLSEX controls = {sizeof(controls), ICC_STANDARD_CLASSES};
    MSG message;
    RECT work;
    POINT cursor;
    HMONITOR monitor;
    MONITORINFO monitor_info = {0};
    BOOL result;
    int exit_code = 0;
    int width, height;
    HWND window;
    enable_dpi_awareness();
    InitCommonControlsEx(&controls);
    ui.instance = instance;
    ui.request=request;ui.result=response;
    ui.dpi = window_dpi(NULL);
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(NULL, IDC_ARROW);
    window_class.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_APP));
    window_class.hIconSm = window_class.hIcon;
    window_class.lpszClassName = WINDOW_CLASS;
    if (!RegisterClassExW(&window_class)) return 1;
    GetCursorPos(&cursor);
    monitor = request && request->owner && IsWindow(request->owner) ? MonitorFromWindow(request->owner,MONITOR_DEFAULTTONEAREST) : MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST);
    monitor_info.cbSize = sizeof(monitor_info);
    if (GetMonitorInfoW(monitor, &monitor_info)) work = monitor_info.rcWork;
    else SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    if (!ui_frame_configure(&ui.frame, ui.dpi, ui_px(ui.dpi, WINDOW_WIDTH),
                             ui_px(ui.dpi, WINDOW_HEIGHT))) {
        UnregisterClassW(WINDOW_CLASS, instance);
        return 1;
    }
    width = ui.frame.layer_width;
    height = ui.frame.layer_height;
    window = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_LAYERED, WINDOW_CLASS, L"Windows 安全中心",
                             WS_POPUP,
                             work.left + (work.right - work.left - width) / 2,
                             work.top + (work.bottom - work.top - height) / 2,
                             width, height, request && IsWindow(request->owner) ? request->owner : NULL, NULL, instance, &ui);
    if (!window) {
        MessageBoxW(NULL, L"无法创建界面窗口。", L"CredentialUI", MB_OK | MB_ICONERROR);
        exit_code = 1;
    } else {
        /* WM_CREATE may discover a different per-monitor DPI. */
        SetWindowPos(window, NULL, 0, 0, ui.frame.layer_width,
                      ui.frame.layer_height,
                      SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        SendMessageW(window, WM_CHANGEUISTATE, MAKEWPARAM(UIS_SET, UISF_HIDEFOCUS), 0);
        credential_ui_set_status(window, L"");
        if(request) {
            SetWindowTextW(ui.username,request->username);
            EnableWindow(ui.remember,request->allow_save);
            SendMessageW(ui.remember,BM_SETCHECK,request->allow_save && request->save?BST_CHECKED:BST_UNCHECKED,0);
            if(request->retry && request->auth_error) {
                WCHAR text[256]={0};FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,NULL,request->auth_error,0,text,256,NULL);
                credential_ui_set_status(window,text[0]?text:L"认证未完成，请检查凭据后重试。");
            }
            SetTimer(window,2,100,NULL);
        }
        render_window(&ui);
        ShowWindow(window, show_command);
        UpdateWindow(window);
        SetFocus(ui.username);
        while ((result = GetMessageW(&message, NULL, 0, 0)) > 0) {
            if (message.message == WM_KEYDOWN) {
                if (message.wParam == VK_ESCAPE) {
                    SendMessageW(window, WM_CLOSE, 0, 0);
                    continue;
                }
                if (message.wParam == VK_RETURN) {
                    HWND focus = GetFocus();
                    SendMessageW(focus == ui.cancel || focus == ui.close ? focus : ui.confirm,
                                  BM_CLICK, 0, 0);
                    continue;
                }
            }
            if (!IsDialogMessageW(window, &message)) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        exit_code = result == -1 ? 1 : (int)message.wParam;
    }
    if (ui.body_font) DeleteObject(ui.body_font);
    if (ui.title_font) DeleteObject(ui.title_font);
    if (ui.heading_font) DeleteObject(ui.heading_font);
    if (ui.title_icon) DestroyIcon(ui.title_icon);
    ui_frame_dispose(&ui.frame);
    UnregisterClassW(WINDOW_CLASS, instance);
    return exit_code;
}

int credential_ui_run(HINSTANCE instance,int show_command) { return run_window(instance,show_command,NULL,NULL); }
DWORD credential_ui_prompt(HINSTANCE instance,int show_command,const CredentialUiRequest *request,CredentialUiResult *result) {
    if(!request||!result)return ERROR_INVALID_PARAMETER;
    SecureZeroMemory(result,sizeof *result);result->result=ERROR_CANCELLED;
    int status=run_window(instance,show_command,request,result);
    if(status){SecureZeroMemory(result,sizeof *result);result->result=ERROR_CANCELLED;return ERROR_GEN_FAILURE;}
    if(result->result!=ERROR_SUCCESS){SecureZeroMemory(result->username,sizeof result->username);SecureZeroMemory(result->password,sizeof result->password);result->save=FALSE;}
    return result->result;
}
