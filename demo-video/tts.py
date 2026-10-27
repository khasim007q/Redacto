"""Generate one voice-over clip per scene and write timing.json.

Each scene lasts as long as its narration plus a short breath, so the motion
is timed to the voice rather than the other way round.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys
from pathlib import Path

import edge_tts

HERE = Path(__file__).resolve().parent
FFMPEG = HERE / "node_modules" / "ffmpeg-static" / "ffmpeg.exe"
LEAD_IN = 0.6  # seconds of silence before each line
TAIL = 0.9  # seconds after each line before the next scene


def duration(path: Path) -> float:
    out = subprocess.run([str(FFMPEG), "-hide_banner", "-i", str(path)], capture_output=True, text=True)
    match = re.search(r"Duration: (\d+):(\d+):([\d.]+)", out.stderr)
    if not match:
        raise RuntimeError(f"no duration for {path}")
    hours, minutes, seconds = match.groups()
    return int(hours) * 3600 + int(minutes) * 60 + float(seconds)


async def main() -> None:
    script = json.loads((HERE / "script.json").read_text(encoding="utf-8"))
    audio = HERE / "build" / "audio"
    audio.mkdir(parents=True, exist_ok=True)
    timing = []
    start = 0.0
    for scene in script["scenes"]:
        clip = audio / f"{scene['id']}.mp3"
        words_file = audio / f"{scene['id']}.words.json"
        if not clip.exists() or not words_file.exists() or "--force" in sys.argv:
            communicate = edge_tts.Communicate(
                scene["text"], script["voice"], rate=script["rate"], boundary="WordBoundary"
            )
            words = []
            with open(clip, "wb") as handle:
                async for chunk in communicate.stream():
                    if chunk["type"] == "audio":
                        handle.write(chunk["data"])
                    elif chunk["type"] == "WordBoundary":
                        # offsets are in 100 ns ticks
                        words.append({"w": chunk["text"], "t": round(chunk["offset"] / 1e7, 3)})
            words_file.write_text(json.dumps(words), encoding="utf-8")
        words = json.loads(words_file.read_text(encoding="utf-8"))
        speech = duration(clip)
        length = round(LEAD_IN + speech + TAIL, 3)
        timing.append(
            {
                "id": scene["id"],
                "start": round(start, 3),
                "duration": length,
                "speech": speech,
                "lead_in": LEAD_IN,
                # word -> seconds from the scene start, used to land motion on the voice
                "words": [{"w": w["w"], "t": round(LEAD_IN + w["t"], 3)} for w in words],
            }
        )
        start += length
    (HERE / "build" / "timing.json").write_text(json.dumps(timing, indent=2), encoding="utf-8")
    print(f"{len(timing)} scenes, {start:.1f} s total")
    for entry in timing:
        print(f"  {entry['id']:<10} {entry['start']:7.1f}  {entry['duration']:5.1f}")


if __name__ == "__main__":
    asyncio.run(main())
