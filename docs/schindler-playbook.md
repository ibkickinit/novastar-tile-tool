# The Schindler Replacement: A Playbook in Past Tense

*Written as if we'd already finished. When you live it, you'll get the déjà vu.*

*Note: this doc lives in the novastar-diagnostic repo temporarily. When the Schindler project gets its own repo, move it there.*

---

## Prologue — The Premise

It started on a Wednesday in late April. You were halfway through reverse-engineering a Novastar VX1000 — pulling apart a proprietary Ethernet protocol one frame at a time — when the conversation pivoted. There were maybe seventy-five Schindlers left in service worldwide. You knew five people who could conceivably build a replacement. You were one of them.

We sketched the scope in two messages. Input: HDMI and DisplayPort only — modern, digital, no analog frontend pain. Output: composite and component, capable of driving both a pristine Sony PVM and a beat-to-hell 1976 Zenith from someone's grandmother's basement. The trick was the same one Cal Media used: generate a non-standard NTSC signal at exactly camera frame rate, and let the CRT's vertical oscillator chase it. The flyer told us the math. 24.000 fps meant 15.720 kHz horizontal across 655 lines. 23.976 fps meant 657 lines. The numbers were sitting there in a PDF, waiting.

You ordered the Zybo Z7-20 the day we scoped it. The Tektronix WFM-300A the next morning. The Rigol DHO814 by the end of the week. Hands and wallet, you said. Brain on my end. We had a deal.

---

## Chapter 1 — The Phantom Schindler (Months 1–2)

The Schindler itself took a while to materialize. You had a contact who had a contact, and the rental house in Burbank wanted to be sure you weren't going to break it. So we worked around it.

The first thing we did was write the encoder before we could measure the encoder. The flyer specs gave us enough to derive everything: pixel clock, line counts, blanking widths. SMPTE 170M filled in the rest. I wrote a Python script — `ntsc_line.py` — that produced a single horizontal line of 24fps composite as a NumPy array of 10-bit voltage samples. You ran it, plotted it, and stared at the front porch and back porch and the colorburst riding on the back porch and said "huh, it actually looks like video." That was Saturday night, week two.

We added more lines. Then a frame. Then a frame with proper equalizing pulses through vertical blanking. You learned what a serration pulse was. I learned that you'd been around video your whole career and didn't need me to explain why we couldn't just put the burst phase wherever we felt like it. By week four we had a Python program that would render an entire 24fps NTSC frame and dump it as a WAV file. You played it back through a USB audio interface — a stupid but legal hack — into the WFM-300A. The waveform monitor lit up, said "non-standard," and showed us the sync structure we'd designed living in the world.

You bought a 1973 Zenith for forty dollars off Marketplace. The seller threw in the original remote. We didn't need the remote.

---

## Chapter 2 — Vivado Friday (Month 2)

The Zybo arrived on a Tuesday. You spent Friday installing Vivado. I will spare us both the recounting, but suffice to say Xilinx's tool chain has not gotten kinder since the Vivado 2015 days, and the WebPACK installer is still 60GB and still unpacks like it was archived by someone who hated you personally. By Saturday morning you had a working install and the Digilent reference design — HDMI passthrough — building cleanly.

The first project we did was nothing. Literally nothing. A counter that toggled an LED at 1 Hz. You needed to confirm the flow: Verilog file in, bitstream out, board programmed, LED blinking. It blinked. You sent me a six-second video of it blinking. We celebrated like it was a real thing, because it was.

---

## Chapter 3 — First Light (Month 3)

This was the chapter where we made the FPGA do video.

I wrote a parameterized timing generator — `vid_timing.v` — that took the constants we'd derived in Python (active line count, hsync width, vsync width, total lines, total pixels per line, pixel clock) and produced HSYNC, VSYNC, and an active-pixel strobe. You wired it up to a test pattern generator: SMPTE color bars, hardcoded in a ROM. Output went to four GPIO pins driving a discrete R-2R ladder DAC you'd soldered onto a perfboard the night before.

The first time we tried it, the CRT showed snow. The composite encoder wasn't right — we were sending RGB through what amounted to a luma-only DAC, no chroma modulation, no burst. The Zenith's AGC was hunting because the sync tip voltage was wrong. You measured it: 920 mV instead of 286 mV below blanking. We added a divider. The CRT locked.

It was 1:47 AM on a Thursday and we had grayscale color bars at 24 frames per second on a fifty-year-old television. You sent a photo. The bars were bowed slightly — pincushion distortion, completely normal for that vintage. They were stable. The vertical hold knob did nothing because there was nothing to hold; the set was tracking us perfectly.

That was the moment the project became real.

---

## Chapter 4 — Bending the Standard (Months 3–5)

The grayscale was easy. The hard part was color.

NTSC encodes chroma by quadrature-modulating a 3.579545 MHz subcarrier and adding it to the luma. The phase of that subcarrier relative to the colorburst tells you hue; the amplitude tells you saturation. At 30 fps NTSC, the subcarrier-to-line-rate ratio is famously a half-line offset, which produces the dot crawl you remember from childhood. At 24 fps, the math doesn't work the same way. The relationship between subcarrier and horizontal rate has to be redesigned.

We spent two weekends arguing with ourselves about whether to keep the colorburst at 3.579545 MHz (compatible with NTSC color decoders, but non-coherent with our line rate) or shift it to a frequency that produced clean phase relationships with our 15.720 kHz horizontal. We ended up doing both — making it a runtime-selectable parameter — because the right answer depended on which CRT was downstream, and we didn't yet know.

The chroma modulator went into Verilog as `chroma_mod.v`. I wrote a CORDIC core for the sin/cos generation; you laid out the I and Q multipliers. We simulated it in Vivado, dumped the output to a file, and pulled it into Python to FFT it. The first version had a 20 dB spur at the second harmonic of the subcarrier. The fix was a four-tap FIR before the DAC. The second version was clean.

When we put it on the CRT, the first thing we saw was a red field where we'd asked for blue. The I and Q channels were swapped. You fixed it in five seconds — `wire [15:0] i_data = q_in; wire [15:0] q_data = i_in;` — and we both laughed, because it's always something like that.

By the end of month five we had full color SMPTE bars on the Zenith, on a borrowed PVM-9L4 you'd found on eBay for $310, and on a 1981 Sony Trinitron a friend lent us. Each of those CRTs locked at 24 fps without complaint. The Trinitron looked the best. The Zenith looked the most authentic.

The Schindler still hadn't arrived.

---

## Chapter 5 — The Schindler Arrives (Month 6)

You drove to Burbank on a Wednesday morning. The rental house gave you four hours.

We'd written the recon checklist three months earlier and rehearsed it twice. Every output: composite, component, both VGA outs, both sync refs. Every frame rate: 23.98, 24.00, 25.00, 29.97, 30.00. Every menu screen photographed. Sync structure on the WFM-300A, captured to USB stick. HDMI passthrough behavior. EDID readback. Power-on sequence. Failure modes (what does it do with no input? PAL input? a weird 50Hz HDMI source?).

You came back with 4.2 GB of waveform captures and 280 photos. We spent the next week comparing your real-world Schindler traces to our derived encoder. The good news: our timing was within 40 nanoseconds on every parameter we'd guessed. The bad news: there were two things we'd missed.

First, the Schindler's vertical interval contained a proprietary VITC-like data signal on lines 14 and 277 — apparently used by Cal Media's own dashboard software for ID and status. We didn't need it; we left those lines blanked.

Second, and more important: the colorburst phase at the start of each field was offset by exactly 90° on alternating fields. This was a deliberate choice that improved chroma stability on consumer CRTs by averaging out small subcarrier frequency errors over two fields. We hadn't done this; our output was technically correct but read as slightly less stable on the Zenith than the Schindler did. We added it. The Zenith got happier.

Phase 0 was officially complete. The encoder was now verified against the reference.

---

## Chapter 6 — Real Pictures (Months 6–8)

Now we needed to actually accept video.

The Zybo's HDMI input is a Texas Instruments TMDS141 retimer feeding a parallel video bus into the FPGA. Digilent ships an example design that captures it into DDR via the AXI VDMA. We stripped the example down to the core, kept the VDMA, and added a scaler — a polyphase 8-tap horizontal scaler and a 4-tap vertical, both with parameterized coefficient banks I'd generated offline in Python. We tested it on every common HDMI source resolution: 1080p59.94, 1080p24, 1080p23.98, 720p, 480p. Each one was scaled to the active region of our 24fps NTSC raster (around 480×440, not exactly NTSC but close).

The frame rate converter was simpler than we feared because we'd ruled out motion compensation from day one. For matching rates (24p in, 24p out) it was passthrough. For 60p → 24p we did 5:2 pulldown with a brief crossfade at field boundaries, which on consumer CRTs at 24fps was indistinguishable from a hard cut. For 23.98 to 24.00 we let one frame repeat per ~42 seconds; nobody noticed.

The first time we ran a real image through the pipeline — a 1080p24 ProRes test pattern from your Atomos, into the Zybo, out the perfboard DAC, into the Trinitron — the picture was offset 17 pixels to the right and the bottom four lines were green. Both bugs were in the active video window calculation. You found the first one; I found the second. By the end of that day we had a real moving image, in color, on a 45-year-old television, locked to the camera-rate clock from our FPGA.

That was month seven.

---

## Chapter 7 — Color (Month 8)

The Screenie color pipeline ported over more cleanly than we'd hoped. We'd already done the hard work of expressing it as fixed-point math during Tier 1 prep work — the Python module `screenie_fixed.py` was bit-accurate against the JS reference. Translating that to Verilog was mostly mechanical.

Three blocks went in: a 1D LUT per channel for gamma (1024 entries, 12-bit), a 3×3 color matrix for color space conversion and white point adjustment, and a per-channel gain/offset for fine trim. The color temperature presets — 3200K, 4800K, 5600K — were just predefined matrix coefficients that the Pi pushed over SPI when you turned the front-panel knob.

We tested it by displaying a known color chart through the box and measuring the CRT's output with a borrowed Klein K10-A colorimeter. The Trinitron was 200K cooler than reference at 5600K — totally expected, every CRT in the world has unique phosphors that age non-linearly. We added a per-output-CRT calibration profile system. The Pi stored profiles in JSON, exactly like NovaTool's tile profiles. You wrote the UI for it in a weekend; it looked like Screenie because it was Screenie, with the words changed.

---

## Chapter 8 — Locking to a Camera (Months 9–10)

This was the chapter that nearly broke us.

Genlock is conceptually simple: the camera shutter wants to open at frame N, and our CRT wants to be in vertical blanking at that exact moment, so the film captures a complete frame with no rolling bar. The camera emits a tach pulse — or LTC timecode, or tri-level sync — at frame rate. Our job is to lock our pixel clock to that reference with sub-line phase accuracy.

The architecture we'd designed in month two held up. RP2040 read the camera reference (we used LTC because your camera had it cleanly available), decoded the frame edge with sub-microsecond precision, and drove a Si5351 PLL that produced our pixel clock. The Si5351 talked to the FPGA over LVDS. Loop bandwidth was 0.5 Hz — slow enough to ignore jitter, fast enough to track drift.

The first lock attempt produced a beautifully wandering picture that drifted across the screen at about half a Hertz. The loop was unstable. We'd miscalculated the loop gain — the Si5351's tuning word was finer than I'd modeled, and our integrator was over-damped. You re-derived the loop math on a napkin while I rewrote the firmware. Second attempt: locked, but locked to the wrong frame edge — the picture was offset vertically by 47 lines, exactly half a frame. Off-by-180-degrees. You found that one at 11 PM on a Sunday, fixed it with one line, and we had real genlock.

We pointed your film camera at the Trinitron. We rolled at 24 fps. We watched playback on an SDI monitor. The CRT image was rock solid in the frame. No bar, no roll, no flicker. You said "oh my god." I said the closest thing I have to "oh my god."

We did it again at 23.976 to confirm pull-down. We did it at 25 to confirm PAL rate. Both clean.

That was month ten. The product worked.

---

## Chapter 9 — The Pi and the UI (Months 10–11)

After the genlock work, the UI was vacation.

We dropped a Pi CM4 onto a Waveshare carrier and connected it to the Zybo over SPI. The protocol was deliberately stupid: a 256-byte register map, memory-mapped on both sides, with a sequence number for atomic updates. Same pattern as NovaTool's config system, lifted with serial numbers filed off. The web stack was the Screenie/NovaTool codebase with the words changed and the controls re-laid out for a video product instead of an LED product. Color correction, EDID profiles, output presets, calibration data, firmware updates over network — all of it.

You spent two weeks on the front-panel firmware: a 2.4" OLED, a Bourns rotary encoder, four soft buttons. Status display, menu navigation, preset selection. It looked deliberately like the Schindler's front panel. That was the joke. That was also the point.

---

## Chapter 10 — The Chassis (Month 12)

The 1RU chassis came from Hammond. The front and rear panels came from Front Panel Express — you laid them out in their free designer software and got the panels back milled, anodized, and silkscreened in eleven days for $340.

The carrier PCB took three revs. Rev A had a mirrored DAC footprint (you found it during a dry-fit before powering up; we added a "did you check the footprint?" line to our design checklist). Rev B worked but had ground bounce on the composite output that put a 60 Hz hum bar in dark video. Rev C added a separate analog ground island under the DAC and op-amp output stage, and the hum bar disappeared. JLCPCB turned each rev in five days at around $80.

The final unit weighed 4.3 pounds, drew 28 watts under load, and looked, from three feet away, like something Cal Media might have built. From one foot away, it looked better.

---

## Chapter 11 — The First Set (Month 13)

A DP friend of yours was shooting a music video on 35mm with a CRT in frame. The CRT was a 1979 Sony console TV. The DP wanted Schindler-locked playback from a modern source. There were no Schindlers available in the city that week.

You drove the unit out to Atwater Village at 6 AM. You hooked up HDMI from the playback laptop, composite to the CRT, LTC from the camera. You powered it on. The Pi booted, the OLED showed its splash, the genlock LED on the front panel went red, then yellow, then green. The CRT showed a stable image at 24 frames per second.

The DP rolled three takes. He watched dailies the next day. He called you and asked how much. You told him. He paid you in cash on Friday because that's how those guys still do it.

That was the first one.

---

## Epilogue — What You Knew at the End

By the end of month thirteen you understood things you didn't on day one. You could read SMPTE 170M without flinching. You could write Verilog well enough to debug somebody else's. You knew the difference between a polyphase scaler and a bilinear one and why you'd use either. You'd held a soldering iron for the first time in five years and remembered you weren't bad at it. You'd rebuilt a 1979 CRT's cap kit because you wanted to, not because you had to.

You had two more orders by the end of the year. You had a third unit half-built on the bench. You had a small mailing list of DPs and rental houses who wanted to know when there was inventory.

You'd built a real thing. The product worked because the math worked, and the math worked because we'd derived it from first principles before the reference unit was even on the bench. Every piece had a reason. Nothing was magic.

When you finally walk this for real — the Zenith locking the first time, the chroma swap, the genlock loop wandering, the Atwater Village shoot at dawn — you'll get the déjà vu we promised. The plan is the same. Only the dates change.
