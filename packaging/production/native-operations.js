(function () {
  'use strict';

  const status = document.getElementById('hg-operation-status');
  if (!status) return;
  const base = new URL(status.dataset.base, location.href);
  const pendingKey = 'homegate:operation:' + base.pathname;
  let busy = false;

  function show(message, state = 'success') {
    status.textContent = message;
    status.classList.toggle('hg-notice-error', state === 'error');
    status.classList.toggle('hg-notice-pending', state === 'pending');
    status.hidden = false;
  }

  async function request(url, values, timeout = 10000) {
    const options = { cache: 'no-store', headers: { Accept: 'application/json' } };
    if (values) {
      options.method = 'POST';
      options.body = new URLSearchParams(values);
    }
    const controller = new AbortController();
    options.signal = controller.signal;
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(url, options);
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || '暂时无法确认操作结果。');
      return data;
    } finally {
      clearTimeout(timer);
    }
  }

  function remember(job) {
    try {
      if (job) sessionStorage.setItem(pendingKey, job);
      else sessionStorage.removeItem(pendingKey);
    } catch (_) { /* The current page can still track the operation. */ }
  }

  async function waitForResult(job, onSaved) {
    const deadline = Date.now() + 330000;
    let saved = false;
    while (Date.now() < deadline) {
      const state = await request(base.pathname + '/compat_job/' + job);
      if (!state.pending) {
        if (!state.result || typeof state.result.ok !== 'boolean') throw new Error('暂时无法确认操作结果。');
        if (!state.result.uncertain) {
          try {
            await request(base.pathname + '/compat_ack/' + job, { token: status.dataset.token }, 2000);
            remember(null);
          } catch (_) { /* Keep the job reference so we can acknowledge it later. */ }
        }
        return state.result;
      }
      if (state.recovery_required) throw new Error('操作中断，请到插件维护检查恢复状态。');
      if (!saved && state.configuration_saved === true) {
        saved = true;
        if (onSaved) onSaved();
        show(state.applying_service === 'stop' ? '配置已保存，正在停用 HomeGate。' :
          '配置已保存，HomeGate 正在启动。', 'pending');
      }
      await new Promise(resolve => setTimeout(resolve, 750));
    }
    throw new Error(saved ? '配置已保存，服务状态仍待确认。' : '操作结果仍待确认。');
  }

  function finish(result, route) {
    if (!result.ok) {
      const prefix = result.configuration_saved && !/^(配置已保存|服务已运行)/.test(result.error || '') ? '配置已保存。' : '';
      let message = result.error || '操作未完成。';
      if (message === 'Native Web operation unavailable; inspect current configuration and retained tasks') {
        const site = /^\d+$/.test(result.error_site || '') ? '（错误位置 ' + result.error_site + '）' : '';
        message = (result.uncertain ? '操作结果待确认，请检查当前配置和服务状态。' : '操作未完成，请检查当前配置后重试。') + site;
      }
      show(prefix + message, 'error');
      if (route === 'basic_apply' && window.hgRefreshService) window.hgRefreshService();
      return;
    }
    const redirect = result.redirect && new URL(result.redirect, base);
    const notice = redirect && redirect.searchParams.get('notice');
    const messages = {
      Saved: '已保存。',
      'Saved and applied': '已保存并应用。',
      'Wake packet sent': '已发送唤醒请求。'
    };
    if (route && redirect && redirect.origin === base.origin && redirect.pathname === location.pathname &&
        (redirect.pathname === base.pathname + '/public' || redirect.pathname === base.pathname + '/wol') &&
        route !== 'wol_action') {
      // These pages have server-assigned identifiers and rows that must be reloaded together.
      location.assign(redirect.href);
      return;
    }
    show(result.runtime_applied ? '已保存，HomeGate 已运行。' : (messages[notice] || notice || '操作已完成。'));
    if (route === 'basic_apply' && window.hgRefreshService) window.hgRefreshService();
  }

  async function run(url, data, form) {
    if (busy) return;
    busy = true;
    const route = url.pathname.slice(base.pathname.length + 1);
    const controls = Array.from(form.elements).filter(element => !element.disabled && element.type !== 'hidden');
    const captureSaved = () => {
      if ((route === 'basic_apply' || route === 'maintenance_apply') && window.hgOperationTracker) {
        window.hgOperationTracker.capture();
      }
    };
    controls.forEach(element => { element.disabled = true; });
    show(data.get('mode') === 'save' ? '正在保存…' : '正在处理…', 'pending');
    try {
      const submitted = await request(url, data);
      if (!submitted.pending || !/^[a-f0-9]{32}$/.test(submitted.job)) throw new Error('暂时无法确认操作结果。');
      remember(submitted.job);
      const result = await waitForResult(submitted.job, () => {
        controls.forEach(element => { element.disabled = false; });
        captureSaved();
        controls.forEach(element => { element.disabled = true; });
      });
      controls.forEach(element => { element.disabled = false; });
      if (result.ok || result.configuration_saved) captureSaved();
      finish(result, route);
    } catch (error) {
      show((error.name === 'AbortError' || error instanceof SyntaxError || error instanceof TypeError ?
        '暂时无法确认操作结果。' : error.message) + ' 请刷新页面查看状态。', 'error');
    } finally {
      controls.forEach(element => { element.disabled = false; });
      busy = false;
    }
  }

  function intercept(form, event) {
    const url = new URL(form.action, location.href);
    if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname + '/') || form.method !== 'post') return;
    const path = url.pathname.slice(base.pathname.length + 1);
    if (path.includes('/') || ['config_import', 'config_export', 'diagnostic_download', 'config_reset', 'log_clear'].includes(path)) return;
    if (event) event.preventDefault();
    const values = new FormData(form);
    if (event && event.submitter && event.submitter.name) values.append(event.submitter.name, event.submitter.value);
    run(url, values, form);
    return true;
  }

  window.hgSubmitOperation = intercept;
  function showUnsavedChanges(event) {
    if (!busy && event.target.closest('.hg-wrap') && status.nextElementSibling.style.display !== 'none') {
      status.hidden = true;
    }
  }
  document.addEventListener('input', showUnsavedChanges);
  document.addEventListener('change', showUnsavedChanges);
  document.addEventListener('submit', event => {
    const form = event.target;
    if (!event.defaultPrevented && form.id === 'hg-migrate-configuration') {
      event.preventDefault();
      if (busy || !confirm('迁移现有 HomeGate 配置并保留原始备份？')) return;
      busy = true;
      const button = form.querySelector('button');
      button.disabled = true;
      show('正在迁移配置…', 'pending');
      const step = (action, values = {}) => request(form.action + '/' + action,
        { token: status.dataset.token, ...values }, 60000);
      (async function () {
        if (form.dataset.copied !== '1') {
          await step('prepare');
          const preview = await step('production_copy_preview');
          if (!preview.report || !/^[a-f0-9]{32}$/.test(preview.report.confirmation || '')) throw new Error();
          await step('production_copy_commit', { confirmation: preview.report.confirmation, consent: '1' });
          form.dataset.copied = '1';
        }
        const preview = await step('activate_preview');
        if (!preview.report || !/^[a-f0-9]{32}$/.test(preview.report.confirmation || '')) throw new Error();
        await step('apply', { confirmation: preview.report.confirmation, consent: '1' });
        form.hidden = true;
        show('配置迁移已完成。');
      })().catch(() => {
        show('迁移未确认。请刷新插件维护页面查看状态。', 'error');
      }).finally(() => {
        button.disabled = false;
        busy = false;
      });
      return;
    }
    if (!event.defaultPrevented && form.id === 'hg-recover-application') {
      event.preventDefault();
      if (busy || !confirm('恢复到上一次应用前的配置？')) return;
      busy = true;
      const button = form.querySelector('button');
      button.disabled = true;
      show('正在恢复配置…', 'pending');
      request(form.action, new FormData(form), 60000).then(() => {
        form.hidden = true;
        show('已恢复应用前配置。');
        location.replace(base.pathname + '/maintenance?notice=' + encodeURIComponent('已恢复应用前配置。'));
      }).catch(() => {
        show('恢复未确认。请检查配置状态或查看其他恢复选项。', 'error');
      }).finally(() => {
        button.disabled = false;
        busy = false;
      });
      return;
    }
    if (!event.defaultPrevented && form instanceof HTMLFormElement) intercept(form, event);
  });

  let pending;
  try { pending = sessionStorage.getItem(pendingKey); } catch (_) { /* Storage may be disabled. */ }
  if (/^[a-f0-9]{32}$/.test(pending)) {
    busy = true;
    show('正在查询上一次操作…', 'pending');
    waitForResult(pending).then(result => {
      finish(result, '');
      if (window.hgRefreshService) window.hgRefreshService();
    }).catch(() => {
      show('上一次操作的结果待确认，请检查服务或配置状态。', 'error');
    }).finally(() => { busy = false; });
  }
})();
