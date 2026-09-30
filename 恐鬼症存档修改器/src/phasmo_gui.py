import os
import subprocess
import sys
import time
import traceback

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import phasmo_save as PS

APP_TITLE = "恐鬼症 存档修改器"
MAX_LEVEL = 9999
MAX_MONEY = 999_999_999
PRESTIGE_LEVEL = 100

XP_PER_LEVEL_ABOVE_100 = 4971


def xp_for_level(level):
    if level <= 1:
        return 0
    if level <= PRESTIGE_LEVEL:
        return int(100.0 * (level - 1) ** 1.73)
    base = int(100.0 * (PRESTIGE_LEVEL - 1) ** 1.73)
    return base + (level - PRESTIGE_LEVEL) * XP_PER_LEVEL_ABOVE_100


def xp_for_target(level):
    lo, hi = xp_for_level(level), xp_for_level(level + 1)
    return (lo + hi) // 2


def level_for_xp(xp):
    if xp <= 0:
        return 1
    lo, hi = 1, MAX_LEVEL
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if xp_for_level(mid) <= xp:
            lo = mid
        else:
            hi = mid - 1
    return lo


def game_running():
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Phasmophobia.exe", "/NH"],
            capture_output=True, text=True, timeout=15,
            creationflags=0x08000000)
        return "Phasmophobia.exe" in (out.stdout or "")
    except Exception:
        return False


def read_save(path):
    text = PS.decrypt_bytes(open(path, "rb").read())
    money = PS.get_value(text, "PlayersMoney")
    xp = PS.get_value(text, "Experience")
    return text, int(money), int(xp)


def write_save(path, text):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = "%s.bak-%s" % (path, stamp)
    with open(backup, "wb") as f:
        f.write(open(path, "rb").read())
    blob = PS.encrypt_bytes(text)
    if PS.decrypt_bytes(blob) != text:
        raise RuntimeError("加密自检失败，已放弃写入")
    with open(path, "wb") as f:
        f.write(blob)
    return backup


class App(ttk.Frame):
    def __init__(self, root):
        super().__init__(root, padding=12)
        self.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        self.save_path = tk.StringVar(value=PS.DEFAULT_SAVE)
        self.money_in = tk.StringVar()
        self.level_in = tk.StringVar()
        self.xp_in = tk.StringVar()
        self.status = tk.StringVar(value="就绪")
        self.cur_info = tk.StringVar(value="尚未读取存档")
        self._syncing = False

        r = 0
        ttk.Label(self, text="存档文件").grid(row=r, column=0, sticky="w", pady=(0, 6))
        ttk.Entry(self, textvariable=self.save_path).grid(
            row=r, column=1, columnspan=2, sticky="ew", pady=(0, 6))
        ttk.Button(self, text="浏览…", width=8, command=self.pick).grid(
            row=r, column=3, padx=(6, 0), pady=(0, 6))

        r += 1
        ttk.Label(self, textvariable=self.cur_info, foreground="#0a6").grid(
            row=r, column=0, columnspan=4, sticky="w", pady=(0, 10))

        sep = ttk.Separator(self, orient="horizontal")
        sep.grid(row=r + 1, column=0, columnspan=4, sticky="ew", pady=(0, 10))
        r += 2

        ttk.Label(self, text="金钱").grid(row=r, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=self.money_in).grid(
            row=r, column=1, columnspan=3, sticky="ew", pady=4)

        r += 1
        ttk.Label(self, text="等级").grid(row=r, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=self.level_in).grid(
            row=r, column=1, columnspan=3, sticky="ew", pady=4)
        self.level_in.trace_add("write", self.on_level_change)

        r += 1
        ttk.Label(self, text="经验值").grid(row=r, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=self.xp_in).grid(
            row=r, column=1, columnspan=3, sticky="ew", pady=4)

        r += 1
        ttk.Label(self, text="改等级 = 写经验值，想精确控制可以直接改经验值",
                  foreground="#888").grid(row=r, column=0, columnspan=4,
                                          sticky="w", pady=(0, 10))

        r += 1
        bar = ttk.Frame(self)
        bar.grid(row=r, column=0, columnspan=4, sticky="ew", pady=(2, 8))
        ttk.Button(bar, text="读取存档", command=self.load).pack(side="left")
        self.apply_btn = ttk.Button(bar, text="应用修改", command=self.apply)
        self.apply_btn.pack(side="left", padx=6)
        ttk.Button(bar, text="退出", command=root.destroy).pack(side="right")

        r += 1
        ttk.Label(self, textvariable=self.status, foreground="#c60",
                  wraplength=430, justify="left").grid(
            row=r, column=0, columnspan=4, sticky="w")

        self.load()

    def pick(self):
        p = filedialog.askopenfilename(title="选择 SaveFile.txt",
                                       filetypes=[("存档", "*.txt"), ("全部", "*.*")])
        if p:
            self.save_path.set(p)
            self.load()

    def on_level_change(self, *_):
        if self._syncing:
            return
        raw = self.level_in.get().strip()
        if not raw.isdigit():
            return
        lv = int(raw)
        if not 1 <= lv <= MAX_LEVEL:
            return
        self._syncing = True
        self.xp_in.set(str(xp_for_target(lv)))
        self._syncing = False

    def load(self):
        try:
            text, money, xp = read_save(self.save_path.get())
        except Exception as e:
            self.cur_info.set("读取失败：%s" % e)
            return
        self._syncing = True
        self.money_in.set(str(money))
        lv = level_for_xp(xp)
        self.level_in.set(str(lv))
        self.xp_in.set(str(xp))
        self._syncing = False
        self.cur_info.set("当前：金钱 %s ｜ 等级 %d（经验 %d）"
                          % (format(money, ","), lv, xp))
        self.status.set("已读取存档")

    def apply(self):
        try:
            money = int(self.money_in.get().strip().replace(",", ""))
            xp = int(self.xp_in.get().strip().replace(",", ""))
        except ValueError:
            messagebox.showerror(APP_TITLE, "金钱和经验值必须是整数。")
            return
        if not 0 <= money <= MAX_MONEY:
            messagebox.showerror(APP_TITLE, "金钱请填 0 ~ %d。" % MAX_MONEY)
            return
        if not 0 <= xp <= xp_for_level(MAX_LEVEL):
            messagebox.showerror(APP_TITLE, "经验值超出范围。")
            return

        path = self.save_path.get()
        if game_running():
            messagebox.showwarning(
                APP_TITLE, "检测到游戏正在运行。\n请先完全退出游戏再修改，"
                           "否则退出游戏时会把改好的存档覆盖掉。")
            return
        if not messagebox.askyesno(
                APP_TITLE,
                "即将写入：\n\n  金钱 = %s\n  经验 = %s（约 %d 级）\n\n"
                "原存档会自动备份。确定吗？"
                % (format(money, ","), format(xp, ","), level_for_xp(xp))):
            return

        try:
            text, _, _ = read_save(path)
            text = PS.set_value(text, "PlayersMoney", money)
            text = PS.set_value(text, "Experience", xp)
            backup = write_save(path, text)
        except Exception:
            messagebox.showerror(APP_TITLE, "写入失败：\n\n" + traceback.format_exc())
            return

        self.status.set("已写入。备份：%s" % os.path.basename(backup))
        self.load()
        messagebox.showinfo(
            APP_TITLE,
            "修改完成。\n\n备份文件：\n%s\n\n"
            "注意：本作接入了 Unity 云存档。如果进游戏发现进度被回滚，"
            "说明云端覆盖了本地存档。" % backup)


def selftest():
    out = sys.stdout
    if out is None:
        return
    for lv in (1, 2, 3, 5, 10, 41, 50, 100, 101, 200, 9999):
        lo, hi = xp_for_level(lv), xp_for_level(lv + 1) if lv < MAX_LEVEL else None
        out.write("lv=%-5d xp_for_level=%-12d target=%-12d %s\n"
                  % (lv, lo, xp_for_target(lv),
                     ("band=%d" % (hi - lo)) if hi is not None else ""))
    out.write("\n")
    for xp in (0, 99, 100, 101, 330, 331, 283440):
        out.write("xp=%-10d -> level %d\n" % (xp, level_for_xp(xp)))


def main():
    if "--selftest" in sys.argv:
        selftest()
        return
    root = tk.Tk()
    root.title(APP_TITLE)
    root.minsize(470, 330)
    try:
        root.call("tk", "scaling", 1.25)
    except Exception:
        pass

    def report(exc, val, tb):
        messagebox.showerror(APP_TITLE, "出错了：\n\n" + "".join(
            traceback.format_exception(exc, val, tb)))
    root.report_callback_exception = report
    sys.excepthook = lambda t, v, tb: report(t, v, tb)

    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
