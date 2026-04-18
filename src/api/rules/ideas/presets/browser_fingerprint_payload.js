(() => {
  const REPORT_ENDPOINT = '/.well-known/waf/browser-fingerprint-report';
  const MAX_REPORTED_ATTEMPTS = 3;
  const REPORT_EVERY_N_ATTEMPTS = 5;
  const challengeState = {
    attempts: 0,
    solved: 0,
    lastReportAtAttempt: 0,
    current: null,
  };

  const collectCanvasFingerprint = () => {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 280;
      canvas.height = 60;
      const ctx = canvas.getContext('2d');
      if (!ctx) return 'canvas-unavailable';
      ctx.textBaseline = 'top';
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = '#f97316';
      ctx.fillRect(12, 10, 180, 28);
      ctx.fillStyle = '#1e293b';
      ctx.fillText('rust-waf-fingerprint', 14, 14);
      ctx.strokeStyle = '#0ea5e9';
      ctx.beginPath();
      ctx.arc(220, 28, 18, 0, Math.PI * 2);
      ctx.stroke();
      return canvas.toDataURL();
    } catch (error) {
      return `canvas-error:${error instanceof Error ? error.message : String(error)}`;
    }
  };

  const collectWebGlFingerprint = () => {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return { vendor: 'unavailable', renderer: 'unavailable' };
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      return {
        vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'masked',
        renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'masked',
      };
    } catch (error) {
      return {
        vendor: 'error',
        renderer: error instanceof Error ? error.message : String(error),
      };
    }
  };

  const collectFonts = async () => {
    const candidates = [
      'Arial',
      'Helvetica',
      'Times New Roman',
      'Courier New',
      'Georgia',
      'Verdana',
      'Trebuchet MS',
      'Tahoma',
      'Consolas',
      'Monaco',
      'PingFang SC',
      'Microsoft YaHei',
      'SimSun',
      'Noto Sans',
      'Roboto',
    ];
    if (!('fonts' in document) || typeof document.fonts?.check !== 'function') {
      return ['font-api-unavailable'];
    }
    const detected = [];
    for (const font of candidates) {
      if (document.fonts.check(`16px "${font}"`)) {
        detected.push(font);
      }
    }
    return detected;
  };

  const sha256Hex = async (value) => {
    if (!globalThis.crypto?.subtle) {
      return '';
    }
    const buffer = new TextEncoder().encode(value);
    const digest = await globalThis.crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(digest))
      .map((item) => item.toString(16).padStart(2, '0'))
      .join('');
  };

  const appendPanel = (title, payload) => {
    const main = document.querySelector('main');
    if (!main) return;
    const wrapper = document.createElement('section');
    wrapper.style.marginTop = '16px';
    wrapper.style.padding = '16px';
    wrapper.style.borderRadius = '12px';
    wrapper.style.background = '#0f172a';
    wrapper.style.color = '#e2e8f0';
    wrapper.style.boxShadow = '0 12px 28px rgba(15, 23, 42, 0.22)';

    const heading = document.createElement('div');
    heading.textContent = title;
    heading.style.fontSize = '12px';
    heading.style.letterSpacing = '0.08em';
    heading.style.textTransform = 'uppercase';
    heading.style.color = '#93c5fd';
    heading.style.marginBottom = '10px';
    wrapper.appendChild(heading);

    const panel = document.createElement('pre');
    panel.style.margin = '0';
    panel.style.fontSize = '12px';
    panel.style.lineHeight = '1.6';
    panel.style.whiteSpace = 'pre-wrap';
    panel.style.wordBreak = 'break-all';
    panel.textContent =
      typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2);
    wrapper.appendChild(panel);
    main.appendChild(wrapper);
  };

  const setMessage = (text, color = '#0f172a') => {
    const message = document.getElementById('message');
    if (!message) return;
    message.textContent = text;
    message.style.color = color;
  };

  const fingerprint = {
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown',
    language: navigator.language || 'unknown',
    languages: Array.isArray(navigator.languages) ? navigator.languages : [],
    platform: navigator.platform || 'unknown',
    userAgent: navigator.userAgent,
    screen: `${window.screen.width}x${window.screen.height}@${window.devicePixelRatio || 1}`,
    viewport: `${window.innerWidth}x${window.innerHeight}`,
    colorDepth: window.screen.colorDepth || 0,
    cookieEnabled: !!navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack || 'unknown',
    hardwareConcurrency: navigator.hardwareConcurrency || 0,
    deviceMemory:
      typeof navigator.deviceMemory === 'number' ? navigator.deviceMemory : null,
    touchPoints: navigator.maxTouchPoints || 0,
    webdriver: !!navigator.webdriver,
    url: window.location.href,
    path: `${window.location.pathname}${window.location.search}`,
    referrer: document.referrer || '',
    title: document.title || '',
    canvas: collectCanvasFingerprint(),
    webgl: collectWebGlFingerprint(),
    fonts: [],
    challenge: {
      name: 'endless-calculus-gauntlet',
      attempts: 0,
      solved: 0,
      current_prompt: '',
      taunt: '',
      started_at: new Date().toISOString(),
    },
    collectedAt: new Date().toISOString(),
  };

  const challengeDefinitions = [
    (difficulty) => {
      const a = difficulty + 2;
      const b = difficulty * 3 + 1;
      return {
        prompt: `设 f(x)=x^${a}- ${b}x + 7，求 f'(x) 在 x=${difficulty + 1} 处的值。`,
        answer: String(a * (difficulty + 1) ** (a - 1) - b),
        bait: '提示：这只是热身题，别误会自己快通关了。',
      };
    },
    (difficulty) => {
      const n = difficulty + 3;
      return {
        prompt: `求极限 lim_{x->0} ((1+${n}x)^(1/x))。`,
        answer: `e^${n}`,
        bait: '别搜公式，搜到也没出口。',
      };
    },
    (difficulty) => {
      const left = difficulty + 1;
      const right = difficulty + 4;
      return {
        prompt: `计算定积分 ∫_${left}^${right} (3x^2 - 2x + 1) dx。`,
        answer: String(
          (right ** 3 - left ** 3) - (right ** 2 - left ** 2) + (right - left),
        ),
        bait: '你现在提交的是答案，不是出路。',
      };
    },
    (difficulty) => {
      const c = difficulty + 2;
      return {
        prompt: `设 y=e^(2x)·sin(${c}x)，求 y'' 在 x=0 处的值。`,
        answer: String(4 * 0 + 4 * c),
        bait: '算二阶导的时候，顺便想想自己为什么会卡在这里。',
      };
    },
    (difficulty) => {
      const a = difficulty + 2;
      return {
        prompt: `已知 g(x)=ln(x^2+${a}x+1)，求 g'(1)。`,
        answer: `${(2 + a) / (1 + a + 2)}`,
        bait: '分母看清楚，反正看清也没奖励。',
      };
    },
  ];

  const successTaunts = [
    '算对了也没用，门还是关着。下一题。',
    '答案接近正确，判断依然是失败。继续。',
    '会算高数不等于能通过验证，别高兴太早。',
    '恭喜浪费了更多算力，奖励是一道更难的题。',
  ];

  const failureTaunts = [
    '这都算不出来，还想继续往前探？下一题。',
    '步骤都没写明白，倒是把时间交出来了。',
    '连热身题都失手，看来自动化脚本今天状态一般。',
    '答案离谱得很稳定，继续做题吧。',
  ];

  const ambientTaunts = [
    '当前验证通道繁忙，你的耐心正在被计入成本。',
    '本页不提供通过路径，只提供更多工作量。',
    '你不是在解锁访问，你是在给画像系统补样本。',
    '继续提交也不会结束，只会更精确地描述你。',
  ];

  const pick = (items) => items[Math.floor(Math.random() * items.length)];

  const createChallenge = (difficulty) => {
    const factory = pick(challengeDefinitions);
    return {
      id: `${difficulty}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      difficulty,
      issuedAt: new Date().toISOString(),
      ...factory(difficulty),
    };
  };

  const challengeElements = (() => {
    const main = document.querySelector('main');
    if (!main) return null;

    const shell = document.createElement('section');
    shell.style.marginTop = '18px';
    shell.style.padding = '18px';
    shell.style.borderRadius = '16px';
    shell.style.background =
      'linear-gradient(145deg, rgba(15,23,42,0.98), rgba(30,41,59,0.95))';
    shell.style.color = '#e2e8f0';
    shell.style.boxShadow = '0 18px 38px rgba(15, 23, 42, 0.24)';
    shell.style.border = '1px solid rgba(59,130,246,0.18)';

    const badge = document.createElement('div');
    badge.textContent = 'Continuous Verification';
    badge.style.fontSize = '11px';
    badge.style.letterSpacing = '0.18em';
    badge.style.textTransform = 'uppercase';
    badge.style.color = '#93c5fd';
    shell.appendChild(badge);

    const title = document.createElement('h2');
    title.textContent = '人工复核中，请先完成高数验证';
    title.style.margin = '10px 0 8px';
    title.style.fontSize = '24px';
    title.style.lineHeight = '1.3';
    shell.appendChild(title);

    const hint = document.createElement('p');
    hint.textContent = pick(ambientTaunts);
    hint.style.margin = '0 0 14px';
    hint.style.color = '#cbd5e1';
    hint.style.lineHeight = '1.7';
    shell.appendChild(hint);

    const prompt = document.createElement('div');
    prompt.style.padding = '14px 16px';
    prompt.style.borderRadius = '12px';
    prompt.style.background = 'rgba(2, 6, 23, 0.72)';
    prompt.style.border = '1px solid rgba(148, 163, 184, 0.18)';
    prompt.style.fontFamily =
      "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace";
    prompt.style.lineHeight = '1.8';
    shell.appendChild(prompt);

    const bait = document.createElement('p');
    bait.style.margin = '12px 0 0';
    bait.style.color = '#fca5a5';
    bait.style.fontSize = '13px';
    shell.appendChild(bait);

    const form = document.createElement('form');
    form.style.marginTop = '16px';
    form.style.display = 'grid';
    form.style.gridTemplateColumns = 'minmax(0, 1fr) auto';
    form.style.gap = '10px';

    const input = document.createElement('input');
    input.type = 'text';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.placeholder = '请输入你的推导结果';
    input.style.padding = '12px 14px';
    input.style.borderRadius = '12px';
    input.style.border = '1px solid rgba(148, 163, 184, 0.24)';
    input.style.background = 'rgba(15, 23, 42, 0.86)';
    input.style.color = '#f8fafc';
    input.style.outline = 'none';

    const submit = document.createElement('button');
    submit.type = 'submit';
    submit.textContent = '提交并继续验证';
    submit.style.padding = '12px 16px';
    submit.style.borderRadius = '12px';
    submit.style.border = 'none';
    submit.style.cursor = 'pointer';
    submit.style.background = 'linear-gradient(135deg, #f97316, #fb7185)';
    submit.style.color = '#fff';
    submit.style.fontWeight = '700';

    form.appendChild(input);
    form.appendChild(submit);
    shell.appendChild(form);

    const status = document.createElement('div');
    status.style.marginTop = '12px';
    status.style.padding = '12px 14px';
    status.style.borderRadius = '12px';
    status.style.background = 'rgba(30, 41, 59, 0.72)';
    status.style.color = '#f8fafc';
    status.style.lineHeight = '1.7';
    shell.appendChild(status);

    const board = document.createElement('div');
    board.style.marginTop = '12px';
    board.style.display = 'flex';
    board.style.flexWrap = 'wrap';
    board.style.gap = '10px';
    shell.appendChild(board);

    const attempts = document.createElement('span');
    const solved = document.createElement('span');
    const level = document.createElement('span');
    [attempts, solved, level].forEach((item) => {
      item.style.padding = '6px 10px';
      item.style.borderRadius = '999px';
      item.style.background = 'rgba(15, 23, 42, 0.8)';
      item.style.border = '1px solid rgba(148, 163, 184, 0.18)';
      item.style.fontSize = '12px';
      board.appendChild(item);
    });

    main.appendChild(shell);
    return { shell, hint, prompt, bait, form, input, submit, status, attempts, solved, level };
  })();

  const updateChallengeBoard = () => {
    if (!challengeElements) return;
    challengeElements.attempts.textContent = `尝试次数 ${challengeState.attempts}`;
    challengeElements.solved.textContent = `判定通过 0`;
    challengeElements.level.textContent = `难度等级 ${
      challengeState.current ? challengeState.current.difficulty : 1
    }`;
  };

  const renderChallenge = (challenge, taunt) => {
    if (!challengeElements) return;
    challengeState.current = challenge;
    fingerprint.challenge.current_prompt = challenge.prompt;
    fingerprint.challenge.taunt = taunt || '';
    challengeElements.prompt.textContent = challenge.prompt;
    challengeElements.bait.textContent = challenge.bait;
    challengeElements.status.textContent = taunt || pick(ambientTaunts);
    challengeElements.hint.textContent = pick(ambientTaunts);
    challengeElements.input.value = '';
    challengeElements.input.focus();
    updateChallengeBoard();
  };

  const shouldReportAttempt = () =>
    challengeState.attempts <= MAX_REPORTED_ATTEMPTS ||
    challengeState.attempts - challengeState.lastReportAtAttempt >= REPORT_EVERY_N_ATTEMPTS;

  const sendPayload = async (payload) => {
    const serialized = JSON.stringify(payload);
    const response = await fetch(REPORT_ENDPOINT, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      credentials: 'omit',
      keepalive: serialized.length < 60_000,
      body: serialized,
    });
    const responseText = await response.text();
    let responsePayload = responseText;
    try {
      responsePayload = JSON.parse(responseText);
    } catch (_) {
      // keep raw response text
    }
    return {
      ok: response.ok,
      status: response.status,
      payload: responsePayload,
    };
  };

  const reportFingerprint = async (phase, extra = {}) => {
    const payload = {
      ...fingerprint,
      phase,
      challenge: {
        ...fingerprint.challenge,
        attempts: challengeState.attempts,
        solved: challengeState.solved,
      },
      ...extra,
    };
    return sendPayload(payload);
  };

  const handleChallengeSubmit = async () => {
    if (!challengeState.current || !challengeElements) return;

    const answer = challengeElements.input.value.trim();
    const exactMatch =
      answer !== '' &&
      answer.replace(/\s+/g, '') === challengeState.current.answer.replace(/\s+/g, '');
    challengeState.attempts += 1;
    fingerprint.challenge.attempts = challengeState.attempts;
    const taunt = exactMatch ? pick(successTaunts) : pick(failureTaunts);
    fingerprint.challenge.taunt = taunt;

    const attemptPayload = {
      phase: 'challenge_attempt',
      challenge_attempt: {
        challenge_id: challengeState.current.id,
        prompt: challengeState.current.prompt,
        expected: challengeState.current.answer,
        submitted: answer,
        exact_match: exactMatch,
        difficulty: challengeState.current.difficulty,
        attempted_at: new Date().toISOString(),
        taunt,
      },
    };

    if (shouldReportAttempt()) {
      challengeState.lastReportAtAttempt = challengeState.attempts;
      try {
        await reportFingerprint('challenge_attempt', attemptPayload);
      } catch (error) {
        console.warn('[rust-waf:challenge-report:error]', error);
      }
    }

    setMessage(
      `验证未通过。已记录第 ${challengeState.attempts} 次尝试，继续完成下一题。`,
      '#b45309',
    );
    renderChallenge(createChallenge(challengeState.attempts + 1), taunt);
  };

  if (challengeElements) {
    challengeElements.form.addEventListener('submit', async (event) => {
      event.preventDefault();
      await handleChallengeSubmit();
    });
    challengeElements.input.addEventListener('paste', (event) => {
      event.preventDefault();
      challengeElements.status.textContent = '还想直接粘贴？至少装得像是在思考。';
    });
  }

  collectFonts()
    .then(async (fonts) => {
      fingerprint.fonts = fonts;
      console.log('[rust-waf:fingerprint]', fingerprint);

      const identitySeed = JSON.stringify({
        timezone: fingerprint.timezone,
        language: fingerprint.language,
        platform: fingerprint.platform,
        userAgent: fingerprint.userAgent,
        screen: fingerprint.screen,
        viewport: fingerprint.viewport,
        canvas: fingerprint.canvas,
        webgl: fingerprint.webgl,
        fonts: fingerprint.fonts,
        webdriver: fingerprint.webdriver,
      });
      const computedFingerprintId = await sha256Hex(identitySeed);
      if (computedFingerprintId) {
        fingerprint.fingerprintId = computedFingerprintId.slice(0, 24);
      }

      const firstChallenge = createChallenge(1);
      renderChallenge(firstChallenge, '欢迎进入无限验证流程，你不会在这里看到通过按钮。');

      const reportResult = await reportFingerprint('initial');
      appendPanel('浏览器指纹', fingerprint);
      appendPanel('上报响应', reportResult.payload);

      if (reportResult.ok) {
        setMessage(
          '浏览器指纹采集并回传成功，干扰式高数验证已启动。',
          '#0369a1',
        );
      } else {
        setMessage(
          `浏览器指纹已采集，但回传失败（HTTP ${reportResult.status}）。验证仍会继续。`,
          '#b91c1c',
        );
      }
    })
    .catch((error) => {
      console.error('[rust-waf:fingerprint:error]', error);
      setMessage(
        `浏览器指纹采集或回传失败：${error instanceof Error ? error.message : String(error)}`,
        '#b91c1c',
      );
      appendPanel('错误详情', {
        error: error instanceof Error ? error.message : String(error),
      });
      renderChallenge(createChallenge(2), '采集失败不影响做题，继续。');
    });
})();
