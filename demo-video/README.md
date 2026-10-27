# Redacto demo video

A narrated, motion-designed walkthrough of Redacto. It runs about 4 min 26 s at
1920×1080, 30 fps, and is built entirely from this folder.

| File | Role |
|---|---|
| `script.json` | Narration for each of the 13 scenes, plus the voice and speaking rate |
| `tts.py` | Generates one voice-over clip per scene with word-level timings, then writes `build/timing.json` |
| `index.html` | The scenes, written as HTML and SVG. `renderAt(t)` draws any moment exactly, and motion lands on the spoken words |
| `render.js` | Drives headless Chrome frame by frame and encodes the frames with the narration into `redacto-demo.mp4` |

The numbers on screen come from a real `python -m redacto demo` run: 5 confirmed
descendants, 7 removed, 2 held for review, 4 preserved, and 0 residuals.

## Rebuild

Requirements: Node 18+, Google Chrome, and Python 3.10+ with `edge-tts`. The voice
comes from Microsoft Edge's online text-to-speech, so only the narration text is sent
to Microsoft.

```bash
npm install
python -m pip install edge-tts
python tts.py
node render.js
```

Run `python tts.py --force` after you edit `script.json`. Scene lengths follow the
narration automatically.

To check the layout without rendering the whole video, render stills at chosen
seconds; they land in `build/stills/`:

```bash
node render.js --stills 10,90,120
```

A full render takes about 10 minutes on a desktop CPU. `build/`, `node_modules/` and
the MP4 are git-ignored.
