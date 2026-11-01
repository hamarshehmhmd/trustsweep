"""Render the narrated demo video: real command output + edge-tts narration.

Usage: python demo/render.py   (needs ffmpeg, edge-tts, Pillow, trustsweep on PATH)
Every terminal scene runs its commands for real and shows the actual output;
each scene lasts exactly as long as its narration.
"""
import asyncio
import os
import re
import shutil
import subprocess
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(HERE, "build")
OUT = os.path.join(ROOT, "demo.mp4")
W, H, FPS = 1280, 720, 24
VOICE = "en-US-AndrewNeural"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BG, FG = (24, 26, 33), (220, 223, 228)
ANSI = {"31": (255, 95, 95), "32": (95, 215, 120), "33": (240, 200, 80), "2": (130, 135, 145)}
PROMPT = "~/acme-api $ "

SCENES = [
    {"kind": "title", "title": "trustsweep", "sub": "find every CA trust store on a machine or image,\nand check them all at once",
     "say": "This is trustsweep, a small open source tool that finds every certificate authority trust store "
            "on a machine or a container image, and checks them all at once."},
    {"kind": "bullets", "title": "The problem",
     "bullets": ["Every runtime keeps its own CA bundle:",
                 "   the OS, certifi in each venv, pip's vendored copy,",
                 "   Java cacerts, Node's built-in list",
                 "Add a corporate CA to the OS store, and Python or Java",
                 "   still fail with CERTIFICATE_VERIFY_FAILED",
                 "Distrust a root, and old copies keep trusting it"],
     "say": "Every runtime keeps its own list of trusted roots. The operating system has one, every Python "
            "virtual environment has certifi, pip has its own copy, Java has cacerts, and Node has a built in list. "
            "So when you add a company root to the OS store, Python and Java still fail with certificate verify failed. "
            "And when a root is distrusted, old copies quietly keep trusting it."},
    {"kind": "term", "cmds": ["trustsweep scan"],
     "say": "trustsweep scan lists every store it can find. On this machine there is the OS bundle, "
            "Python's certifi, the separate copy that pip vendors, and Node's built in roots. "
            "They don't even agree on how many certificates they hold."},
    {"kind": "term", "cmds": ["trustsweep scan --root ./rootfs",
                              "trustsweep find corp-root.pem --root ./rootfs"],
     "say": "It can also scan a filesystem tree, like an exported container image. This image has our company "
            "root CA in the OS bundle. But trustsweep find shows it is only in one of the three stores. "
            "The Python virtual environment and the Java keystore don't have it."},
    {"kind": "term", "cmds": ["trustsweep check --require corp-root.pem --root ./rootfs",
                              "echo \"exit code: $?\""],
     "say": "For CI, trustsweep check fails when any store breaks a rule. Here every store must contain the "
            "company CA, so two stores fail, each with a hint on how to fix that runtime. "
            "You can also forbid a distrusted root, or fail on expired and soon to expire certificates."},
    {"kind": "term", "cmds": ["trustsweep diff system node"],
     "say": "And diff compares any two bundles. Here the OS bundle and Node's built in roots differ "
            "by a handful of certificates."},
    {"kind": "bullets", "title": "Try it",
     "bullets": ["curl -fsSL https://raw.githubusercontent.com/",
                 "   hamarshehmhmd/trustsweep/main/install.sh | sh",
                 "trustsweep scan  ·  find  ·  check  ·  diff",
                 "", "Zero dependencies  ·  43 tests  ·  AGPL-3.0 licensed",
                 "Reads PEM, DER, cert dirs and Java JKS keystores"],
     "say": "trustsweep has no dependencies and ships with forty three tests. It reads P E M and D E R files, "
            "certificate folders, and Java keystores. It is licensed under the A G P L version 3, "
            "and it's on GitHub at hamarsheh m h m d slash trustsweep."},
]


async def tts(text, path):
    import edge_tts
    await edge_tts.Communicate(text, VOICE, rate="+4%").save(path)


def duration(path):
    out = subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                                   "-of", "csv=p=0", path], text=True)
    return float(out.strip())


def run_cmd(cmd, cwd):
    env = dict(os.environ, HOME=os.path.dirname(cwd), NO_COLOR="")
    env.pop("NO_COLOR")
    full = re.sub(r"^trustsweep (\w+)", r"trustsweep \1 --color always", cmd)
    p = subprocess.run(["bash", "-c", full], cwd=cwd, capture_output=True, text=True, env=env)
    out = (p.stdout + p.stderr).rstrip("\n")
    # pretty-print hook JSON
    if out.startswith("{"):
        import json
        try:
            out = json.dumps(json.loads(out), indent=2)
        except ValueError:
            pass
    return out


def parse_ansi(line):
    """Return [(text, color, bold)] spans for a line with SGR codes."""
    spans, color, bold = [], FG, False
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        m = re.match(r"\x1b\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    color, bold = FG, False
                elif code == "1":
                    bold = True
                elif code in ANSI:
                    color = ANSI[code]
        elif part:
            spans.append((part, color, bold))
    return spans


class Term:
    def __init__(self):
        self.font = ImageFont.truetype(MONO, 19)
        self.bold = ImageFont.truetype(MONO_B, 19)
        self.cw = self.font.getlength("M")
        self.lh = 27
        self.cols = int((W - 80) / self.cw)

    def wrap(self, spans):
        lines, cur, n = [], [], 0
        for text, c, b in spans:
            while text:
                room = self.cols - n
                if len(text) <= room:
                    cur.append((text, c, b)); n += len(text); text = ""
                else:
                    cur.append((text[:room], c, b)); lines.append(cur); cur, n = [], 0
                    text = "    " + text[room:]
        lines.append(cur)
        return lines

    def frame(self, lines, cursor=False):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([20, 14, W - 20, H - 14], 12, fill=(30, 33, 41), outline=(60, 64, 76))
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([40 + i * 24, 30, 54 + i * 24, 44], fill=c)
        d.text((W // 2, 37), "trustsweep demo — bash", font=ImageFont.truetype(SANS, 15), fill=(150, 155, 165), anchor="mm")
        visible = lines[-23:]
        y = 64
        for ln in visible:
            x = 40
            for text, c, b in ln:
                d.text((x, y), text, font=self.bold if b else self.font, fill=c)
                x += self.cw * len(text)
            y += self.lh
        if cursor:
            last = visible[-1] if visible else []
            x = 40 + self.cw * sum(len(t) for t, _, _ in last)
            d.rectangle([x, y - self.lh + 3, x + self.cw - 2, y - 4], fill=FG)
        return img


def card(scene):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    if scene["kind"] == "title":
        d.text((W // 2, 280), scene["title"], font=ImageFont.truetype(MONO_B, 84), fill=(95, 215, 120), anchor="mm")
        d.multiline_text((W // 2, 420), scene["sub"], font=ImageFont.truetype(SANS, 34), fill=FG, anchor="mm",
                         align="center", spacing=12)
        d.text((W // 2, 620), "github.com/hamarshehmhmd/trustsweep  ·  AGPL-3.0", font=ImageFont.truetype(SANS, 22),
               fill=(150, 155, 165), anchor="mm")
    else:
        d.text((90, 90), scene["title"], font=ImageFont.truetype(SANS_B, 52), fill=(95, 215, 120))
        f = ImageFont.truetype(SANS, 29)
        y = 200
        for b in scene["bullets"]:
            if b and not b.startswith("   "):
                d.text((90, y), "•", font=f, fill=(240, 200, 80))
            d.text((130, y), b.strip(), font=f, fill=FG)
            y += 58 if b.startswith("   ") or not b else 62
    return img


class Writer:
    def __init__(self, path, audio):
        self.p = subprocess.Popen(["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
                                   "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-", "-i", audio,
                                   "-af", "apad", "-c:v", "libx264", "-preset", "medium", "-crf", "23",
                                   "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-ar", "44100",
                                   "-shortest", path], stdin=subprocess.PIPE)
        self.n = 0

    def put(self, img, count=1):
        data = img.tobytes()
        for _ in range(count):
            self.p.stdin.write(data)
        self.n += count

    def close(self):
        self.p.stdin.close()
        self.p.wait()
        if self.p.returncode:
            sys.exit("ffmpeg failed")


def render_scene(i, scene, workdir):
    audio = os.path.join(BUILD, f"s{i}.mp3")
    if not os.path.exists(audio):
        asyncio.run(tts(scene["say"], audio))
    total = int((duration(audio) + 0.7) * FPS)
    path = os.path.join(BUILD, f"s{i}.mp4")
    w = Writer(path, audio)
    if scene["kind"] != "term":
        w.put(card(scene), total)
        w.close()
        return path
    t = Term()
    shown = scene.get("show", scene["cmds"])
    outputs = [run_cmd(c, workdir) for c in scene["cmds"]]
    # When a scene's displayed command differs from what runs (heredoc), show
    # the display lines; the last displayed line always maps to the last command.
    steps = []
    if len(shown) != len(scene["cmds"]):
        steps = [(s, "") for s in shown[:-1]] + [(shown[-1], outputs[-1])]
    else:
        steps = list(zip(shown, outputs))
    # timing budget: typing ~ 30 chars/s, then pause, spread over the narration
    typing = sum(len(s) for s, _ in steps) / 32 * FPS
    pause = max(6, int((total - typing) / max(1, len(steps))) - 4)
    lines = []
    for cmd, out in steps:
        prompt = [(PROMPT, (95, 215, 120), True)]
        for k in range(0, len(cmd) + 1, 2):
            frame = t.frame(lines + t.wrap(prompt + [(cmd[:k], FG, False)]), cursor=True)
            w.put(frame)
        lines += t.wrap(prompt + [(cmd, FG, False)])
        for ol in out.splitlines():
            lines += t.wrap(parse_ansi(ol))
        lines.append([])
        hold = min(pause, max(0, total - w.n))
        w.put(t.frame(lines), hold)
    final = t.frame(lines + t.wrap([(PROMPT, (95, 215, 120), True)]), cursor=True)
    if w.n < total:
        w.put(final, total - w.n)
    w.close()
    return path


def main():
    os.makedirs(BUILD, exist_ok=True)
    sandbox = os.environ.get("DEMO_HOME", "/home/dev")  # shown as $HOME in the demo
    shutil.rmtree(sandbox, ignore_errors=True)
    workdir = os.path.join(sandbox, "acme-api")
    os.makedirs(workdir)
    subprocess.run([sys.executable, os.path.join(HERE, "make_rootfs.py"), os.path.join(workdir, "rootfs")], check=True)
    shutil.copy(os.path.join(ROOT, "tests", "fixtures", "corp-root.pem"), workdir)
    parts = [render_scene(i, s, workdir) for i, s in enumerate(SCENES)]
    with open(os.path.join(BUILD, "list.txt"), "w") as fh:
        fh.writelines(f"file '{p}'\n" for p in parts)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i",
                    os.path.join(BUILD, "list.txt"), "-c:v", "libx264", "-crf", "23", "-pix_fmt", "yuv420p",
                    "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart", OUT], check=True)
    with open(os.path.join(BUILD, "narration.txt"), "w") as fh:
        fh.write("\n\n".join(s["say"] for s in SCENES) + "\n")
    print(OUT, round(duration(OUT), 1), "s")


if __name__ == "__main__":
    main()
