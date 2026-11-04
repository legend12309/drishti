/**
 * SoundEngine.ts
 * Zero-dependency Procedural Web Audio API Synthesizer
 * Custom crafted for DRISHTI // VISION C2 Biometric Terminal & Cyber Lab
 */

class SoundEngine {
  private ctx: AudioContext | null = null;
  private subBassGain: GainNode | null = null;
  private subBassOsc1: OscillatorNode | null = null;
  private subBassOsc2: OscillatorNode | null = null;
  private telemetryInterval: any = null;

  private initContext() {
    if (!this.ctx) {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (AudioCtx) {
        this.ctx = new AudioCtx();
      }
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {});
    }
  }

  /**
   * 1. Sub-Bass Drone: 55Hz sine + 110Hz triangle with 180Hz low-pass filter
   */
  public playSubBassDrone(durationMs = 2800) {
    try {
      this.initContext();
      if (!this.ctx) return;

      this.stopSubBassDrone();

      const now = this.ctx.currentTime;
      const filter = this.ctx.createBiquadFilter();
      filter.type = 'lowpass';
      filter.frequency.setValueAtTime(180, now);
      filter.Q.setValueAtTime(1.5, now);

      const masterGain = this.ctx.createGain();
      masterGain.gain.setValueAtTime(0.001, now);
      masterGain.gain.exponentialRampToValueAtTime(0.18, now + 0.3);
      masterGain.gain.exponentialRampToValueAtTime(0.001, now + durationMs / 1000);

      // Osc 1: 55Hz Sine (Fundamental sub)
      const osc1 = this.ctx.createOscillator();
      osc1.type = 'sine';
      osc1.frequency.setValueAtTime(55, now);

      // Osc 2: 110Hz Triangle (Harmonic grit)
      const osc2 = this.ctx.createOscillator();
      osc2.type = 'triangle';
      osc2.frequency.setValueAtTime(110, now);

      const oscGain = this.ctx.createGain();
      oscGain.gain.setValueAtTime(0.6, now);

      osc1.connect(filter);
      osc2.connect(oscGain);
      oscGain.connect(filter);
      filter.connect(masterGain);
      masterGain.connect(this.ctx.destination);

      osc1.start(now);
      osc2.start(now);

      const stopTime = now + durationMs / 1000 + 0.1;
      osc1.stop(stopTime);
      osc2.stop(stopTime);

      this.subBassGain = masterGain;
      this.subBassOsc1 = osc1;
      this.subBassOsc2 = osc2;
    } catch {
      // Audio fallback fail-safe
    }
  }

  public stopSubBassDrone() {
    try {
      if (this.subBassGain && this.ctx) {
        this.subBassGain.gain.linearRampToValueAtTime(0.0001, this.ctx.currentTime + 0.05);
      }
      setTimeout(() => {
        try {
          this.subBassOsc1?.stop();
          this.subBassOsc2?.stop();
          this.subBassOsc1?.disconnect();
          this.subBassOsc2?.disconnect();
        } catch {}
      }, 60);
    } catch {}
  }

  /**
   * 2. Telemetry Ticks: High-passed white noise bursts (8ms duration, 4200Hz bandpass) every 65ms
   */
  public playTelemetryTicks() {
    this.startTelemetryTicks();
  }

  public startTelemetryTicks() {
    this.stopTelemetryTicks();
    this.initContext();
    if (!this.ctx) return;

    const fireTick = () => {
      try {
        if (!this.ctx) return;
        const now = this.ctx.currentTime;
        const sampleRate = this.ctx.sampleRate;
        const bufferSize = Math.floor(sampleRate * 0.008); // 8ms buffer
        const buffer = this.ctx.createBuffer(1, bufferSize, sampleRate);
        const data = buffer.getChannelData(0);
        for (let i = 0; i < bufferSize; i++) {
          data[i] = Math.random() * 2 - 1;
        }

        const noise = this.ctx.createBufferSource();
        noise.buffer = buffer;

        const filter = this.ctx.createBiquadFilter();
        filter.type = 'bandpass';
        filter.frequency.setValueAtTime(4200, now);
        filter.Q.setValueAtTime(3.8, now);

        const gain = this.ctx.createGain();
        gain.gain.setValueAtTime(0.09, now);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.008);

        noise.connect(filter);
        filter.connect(gain);
        gain.connect(this.ctx.destination);

        noise.start(now);
        noise.stop(now + 0.009);
      } catch {}
    };

    fireTick();
    this.telemetryInterval = setInterval(fireTick, 65);
  }

  public stopTelemetryTicks() {
    if (this.telemetryInterval) {
      clearInterval(this.telemetryInterval);
      this.telemetryInterval = null;
    }
  }

  /**
   * 3. Iris Lock Chirp: Dual-oscillator frequency sweep (280Hz -> 1760Hz over 140ms, exponential ramp)
   */
  public playIrisLockChirp() {
    try {
      this.initContext();
      if (!this.ctx) return;
      const now = this.ctx.currentTime;
      const dur = 0.14; // 140ms

      const masterGain = this.ctx.createGain();
      masterGain.gain.setValueAtTime(0.001, now);
      masterGain.gain.linearRampToValueAtTime(0.16, now + 0.02);
      masterGain.gain.exponentialRampToValueAtTime(0.0001, now + dur);

      // Osc 1: Sine 280Hz -> 1760Hz
      const osc1 = this.ctx.createOscillator();
      osc1.type = 'sine';
      osc1.frequency.setValueAtTime(280, now);
      osc1.frequency.exponentialRampToValueAtTime(1760, now + dur);

      // Osc 2: Triangle (an octave higher harmonic: 560Hz -> 3520Hz)
      const osc2 = this.ctx.createOscillator();
      osc2.type = 'triangle';
      osc2.frequency.setValueAtTime(560, now);
      osc2.frequency.exponentialRampToValueAtTime(3520, now + dur);

      const osc2Gain = this.ctx.createGain();
      osc2Gain.gain.setValueAtTime(0.35, now);

      osc1.connect(masterGain);
      osc2.connect(osc2Gain);
      osc2Gain.connect(masterGain);
      masterGain.connect(this.ctx.destination);

      osc1.start(now);
      osc2.start(now);
      osc1.stop(now + dur + 0.01);
      osc2.stop(now + dur + 0.01);
    } catch {}
  }

  /**
   * 4. Eyelid Shut & CRT Optic Flash:
   * Mechanical transient (120Hz -> 30Hz in 90ms) followed by
   * resonant cinematic sub-boom (80Hz -> 24Hz over 650ms with subtle synthetic tail)
   */
  public playEyelidShutAndFlash() {
    try {
      this.initContext();
      if (!this.ctx) return;
      const now = this.ctx.currentTime;

      // Part A: Mechanical Transient Shutter Snap (120Hz -> 30Hz pitch drop in 90ms)
      const snapOsc = this.ctx.createOscillator();
      snapOsc.type = 'sawtooth';
      snapOsc.frequency.setValueAtTime(120, now);
      snapOsc.frequency.exponentialRampToValueAtTime(30, now + 0.09);

      const snapFilter = this.ctx.createBiquadFilter();
      snapFilter.type = 'lowpass';
      snapFilter.frequency.setValueAtTime(380, now);

      const snapGain = this.ctx.createGain();
      snapGain.gain.setValueAtTime(0.25, now);
      snapGain.gain.exponentialRampToValueAtTime(0.001, now + 0.09);

      snapOsc.connect(snapFilter);
      snapFilter.connect(snapGain);
      snapGain.connect(this.ctx.destination);

      snapOsc.start(now);
      snapOsc.stop(now + 0.1);

      // Part B: Resonant Cinematic Sub-Boom (80Hz -> 24Hz over 650ms)
      const boomTime = now + 0.07;
      const boomOsc = this.ctx.createOscillator();
      boomOsc.type = 'sine';
      boomOsc.frequency.setValueAtTime(80, boomTime);
      boomOsc.frequency.exponentialRampToValueAtTime(24, boomTime + 0.65);

      const boomGain = this.ctx.createGain();
      boomGain.gain.setValueAtTime(0.001, boomTime);
      boomGain.gain.linearRampToValueAtTime(0.35, boomTime + 0.03);
      boomGain.gain.exponentialRampToValueAtTime(0.001, boomTime + 0.65);

      // Simple multi-tap synthetic delay tail (simulates hangar/cockpit acoustic reverberation)
      const delay = this.ctx.createDelay(0.2);
      delay.delayTime.setValueAtTime(0.08, boomTime);
      const delayFeedback = this.ctx.createGain();
      delayFeedback.gain.setValueAtTime(0.3, boomTime);

      boomOsc.connect(boomGain);
      boomGain.connect(this.ctx.destination);
      boomGain.connect(delay);
      delay.connect(delayFeedback);
      delayFeedback.connect(delay);
      delayFeedback.connect(this.ctx.destination);

      boomOsc.start(boomTime);
      boomOsc.stop(boomTime + 0.7);
    } catch {}
  }
}

export const soundEngine = new SoundEngine();
