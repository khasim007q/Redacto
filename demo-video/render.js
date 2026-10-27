// Render the motion design frame by frame and encode it with the narration.
// usage: node render.js [--stills t1,t2,...] [--fps 30] [--from s --to s]
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const puppeteer = require('puppeteer-core');
const ffmpeg = require('ffmpeg-static');

const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const build = path.join(__dirname, 'build');
const timing = JSON.parse(fs.readFileSync(path.join(build, 'timing.json'), 'utf8'));
const total = timing.reduce((s, e) => s + e.duration, 0);

async function page() {
  const browser = await puppeteer.launch({ executablePath: CHROME, headless: true, args: ['--force-color-profile=srgb', '--hide-scrollbars'] });
  const p = await browser.newPage();
  await p.setViewport({ width: 1920, height: 1080, deviceScaleFactor: 1 });
  await p.goto(require('url').pathToFileURL(path.join(__dirname, 'index.html')).href);
  await p.evaluate(t => window.init(t), timing);
  const errors = [];
  p.on('pageerror', e => errors.push(String(e)));
  return { browser, p, errors };
}

async function stills(list) {
  const { browser, p, errors } = await page();
  fs.mkdirSync(path.join(build, 'stills'), { recursive: true });
  for (const t of list) {
    await p.evaluate(x => window.renderAt(x), t);
    await p.screenshot({ path: path.join(build, 'stills', `t${String(t).padStart(6, '0')}.png`) });
  }
  if (errors.length) console.log('page errors:', errors);
  await browser.close();
}

function narration() {
  // one track: each clip delayed to its scene start
  const inputs = [], filters = [];
  timing.forEach((e, i) => {
    inputs.push('-i', path.join(build, 'audio', `${e.id}.mp3`));
    const ms = Math.round((e.start + e.lead_in) * 1000);
    filters.push(`[${i}:a]adelay=${ms}|${ms},aresample=48000[a${i}]`);
  });
  const mix = timing.map((_, i) => `[a${i}]`).join('') + `amix=inputs=${timing.length}:normalize=0,apad,atrim=0:${total.toFixed(3)}[out]`;
  const out = path.join(build, 'narration.wav');
  const r = require('child_process').spawnSync(ffmpeg, ['-y', '-hide_banner', '-loglevel', 'error', ...inputs, '-filter_complex', filters.join(';') + ';' + mix, '-map', '[out]', '-ac', '2', out]);
  if (r.status !== 0) throw new Error(String(r.stderr));
  return out;
}

async function video() {
  const fps = Number(opt('--fps', 30));
  const from = Number(opt('--from', 0)), to = Number(opt('--to', total));
  const audio = narration();
  const out = path.join(__dirname, opt('--out', 'redacto-demo.mp4'));
  const enc = spawn(ffmpeg, ['-y', '-hide_banner', '-loglevel', 'error',
    '-f', 'image2pipe', '-framerate', String(fps), '-c:v', 'mjpeg', '-i', '-',
    '-ss', String(from), '-t', String(to - from), '-i', audio,
    '-c:v', 'libx264', '-preset', 'medium', '-crf', '18', '-pix_fmt', 'yuv420p', '-r', String(fps),
    '-af', 'loudnorm=I=-16:TP=-1.5:LRA=11', '-c:a', 'aac', '-b:a', '192k', '-shortest', '-movflags', '+faststart', out], { stdio: ['pipe', 'inherit', 'inherit'] });
  const { browser, p, errors } = await page();
  const frames = Math.round((to - from) * fps);
  const started = Date.now();
  for (let f = 0; f < frames; f++) {
    await p.evaluate(x => window.renderAt(x), from + f / fps);
    const jpg = await p.screenshot({ type: 'jpeg', quality: 92 });
    if (!enc.stdin.write(jpg)) await new Promise(r => enc.stdin.once('drain', r));
    if (f % 300 === 0) console.log(`frame ${f}/${frames} (${((Date.now() - started) / 1000).toFixed(0)} s)`);
  }
  enc.stdin.end();
  await new Promise(r => enc.on('close', r));
  await browser.close();
  if (errors.length) console.log('page errors:', errors);
  console.log('wrote', out);
}

(async () => {
  const s = opt('--stills');
  if (s) await stills(s.split(',').map(Number));
  else await video();
})().catch(e => { console.error(e); process.exit(1); });
