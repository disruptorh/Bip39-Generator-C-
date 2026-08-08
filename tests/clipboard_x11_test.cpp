// Headless integration test for the secure clipboard (requires an X server).
// Verifies that:
//   1. set_text() makes the text available to a second X connection (i.e. a
//      real paste by another application).
//   2. After the configured timeout, the selection is released AND the private
//      buffer is zeroed (auto-clear).
#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>

#include <X11/Xlib.h>

#include "clipboard/secure_clipboard.hpp"

namespace {

std::uint64_t now_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

// Reads the CLIPBOARD selection through a fresh X connection, as another
// application would. `cb` is polled inside the wait loop so that selection
// requests on the owner's connection are serviced. Returns true and fills
// `out` on success.
bool read_clipboard(Display* dpy, Window win, const std::string& utf8_atom_name,
                    const std::string& clipboard_atom_name,
                    clipboard::secure_clipboard* cb, std::string* out) {
  Atom utf8 = XInternAtom(dpy, utf8_atom_name.c_str(), False);
  Atom clip = XInternAtom(dpy, clipboard_atom_name.c_str(), False);
  Atom sel_prop = XInternAtom(dpy, "BIP39_TEST_PROP", False);
  XConvertSelection(dpy, clip, utf8, sel_prop, win, CurrentTime);
  XFlush(dpy);

  // Wait for SelectionNotify (bounded), servicing the owner connection.
  const auto deadline = now_ms() + 2000;
  bool ok = false;
  while (now_ms() < deadline) {
    cb->poll(now_ms());
    while (XPending(dpy) > 0) {
      XEvent ev;
      XNextEvent(dpy, &ev);
      if (ev.type == SelectionNotify && ev.xselection.selection == clip &&
          ev.xselection.property == sel_prop) {
        ok = (ev.xselection.property != None);
        break;
      }
    }
    if (ok) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  if (!ok) return false;

  Atom type = None;
  int format = 0;
  unsigned long nitems = 0;
  unsigned long bytes_after = 0;
  unsigned char* data = nullptr;
  if (XGetWindowProperty(dpy, win, sel_prop, 0, 4096 / 4, True, AnyPropertyType,
                         &type, &format, &nitems, &bytes_after, &data) !=
      Success) {
    return false;
  }
  if (data != nullptr) {
    out->assign(reinterpret_cast<char*>(data), nitems);
    XFree(data);
  }
  return true;
}

}  // namespace

int main() {
  Display* reader_dpy = XOpenDisplay(nullptr);
  if (reader_dpy == nullptr) {
    std::fprintf(stderr, "SKIP: no X display available\n");
    return 77;  // treat as skip
  }
  Window reader_win = XCreateSimpleWindow(reader_dpy, DefaultRootWindow(reader_dpy),
                                          0, 0, 10, 10, 0, 0, 0);

  clipboard::secure_clipboard cb;
  if (!cb.init()) {
    std::fprintf(stderr, "FAIL: secure_clipboard init\n");
    return 1;
  }
  cb.set_timeout_ms(1500);

  const std::string secret = "super-secret-bip39-mnemonic-value";
  cb.set_text(secret.data(), secret.size());

  // 1) Text must be readable while owned.
  std::string got;
  const auto read_deadline = now_ms() + 2000;
  bool read_ok = false;
  while (now_ms() < read_deadline) {
    cb.poll(now_ms());
    got.clear();
    if (read_clipboard(reader_dpy, reader_win, "UTF8_STRING", "CLIPBOARD",
                       &cb, &got) &&
        got == secret) {
      read_ok = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
  }
  if (!read_ok) {
    std::fprintf(stderr, "FAIL: clipboard text not readable (got '%s')\n",
                 got.c_str());
    return 1;
  }
  std::printf("PASS: clipboard text served correctly\n");

  // 2) After the timeout the selection must be gone and the buffer wiped.
  // Re-claim the text now so the countdown starts deterministically after the
  // read phase, then wait for the ownership to drop.
  cb.set_timeout_ms(1500);
  cb.set_text(secret.data(), secret.size());
  Atom clip = XInternAtom(reader_dpy, "CLIPBOARD", False);
  const Window our_win = XGetSelectionOwner(reader_dpy, clip);

  const auto drop_deadline = now_ms() + 4000;
  bool dropped = false;
  while (now_ms() < drop_deadline) {
    cb.poll(now_ms());
    if (!cb.is_owned() && !cb.has_pending()) {
      dropped = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
  }
  if (!dropped) {
    std::fprintf(stderr, "FAIL: clipboard was not auto-cleared\n");
    return 1;
  }

  // Server side: the CLIPBOARD selection must no longer be ours (either
  // unowned or taken over by another client after we wiped our copy).
  const auto owner_deadline = now_ms() + 2000;
  bool released = false;
  while (now_ms() < owner_deadline) {
    cb.poll(now_ms());
    if (XGetSelectionOwner(reader_dpy, clip) != our_win) {
      released = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  if (!released) {
    std::fprintf(stderr,
                 "FAIL: selection still owned after clear (owner=%lu)\n",
                 (unsigned long)XGetSelectionOwner(reader_dpy, clip));
    return 1;
  }

  std::printf("PASS: clipboard auto-cleared after timeout\n");
  cb.shutdown();
  XDestroyWindow(reader_dpy, reader_win);
  XCloseDisplay(reader_dpy);
  return 0;
}
