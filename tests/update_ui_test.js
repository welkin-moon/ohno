'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

async function main() {
  const handlers = {}, windowHandlers = {};
  const button = {disabled: false};
  const cancel = {disabled: true, addEventListener: (event, cb) => handlers.cancel = cb};
  const status = {textContent: ''};
  const input = {files: [{size: 2048, name: 'fixture.ohno'}]};
  const form = {elements: {csrf: {value: 'fixture-csrf'}},
    querySelector: selector => selector === 'button[type="submit"]' ? button : input,
    addEventListener: (event, cb) => handlers.submit = cb};
  const document = {getElementById: id => ({'update-approval': form, 'cancel-update-upload': cancel, 'update-upload-status': status}[id])};
  let calls = 0, resolve, reject, lastRequest, reloads = 0;
  function fetch(path, request) {
    calls++; assert.equal(path, '/updates/approve'); lastRequest = request;
    return new Promise((yes, no) => {
      resolve = yes; reject = no;
      request.signal.addEventListener('abort', () => no(new Error('fixture abort')));
    });
  }
  vm.runInNewContext(fs.readFileSync('teacher/update_ui.js', 'utf8'), {
    document, window: {addEventListener: (name, cb) => windowHandlers[name] = cb},
    fetch, AbortController, location: {reload: () => reloads++},
  });
  const event = {preventDefault() {}};
  let first = handlers.submit(event); await handlers.submit(event);
  assert.equal(calls, 1); assert.equal(button.disabled, true); assert.equal(cancel.disabled, false);
  assert.equal(lastRequest.redirect, 'error'); assert.equal(lastRequest.headers['X-Ohno-CSRF'], 'fixture-csrf');
  handlers.cancel(); await first;
  assert.equal(lastRequest.signal.aborted, true); assert.equal(button.disabled, false);
  assert.match(status.textContent, /未确认/); assert.equal(reloads, 0);
  first = handlers.submit(event); resolve({ok: true}); await first;
  assert.equal(calls, 2); assert.equal(reloads, 1);
  first = handlers.submit(event); resolve({ok: false}); await first;
  assert.equal(reloads, 1); assert.match(status.textContent, /刷新/);
  first = handlers.submit(event); windowHandlers.pagehide(); await first;
  assert.equal(lastRequest.signal.aborted, true); assert.equal(button.disabled, false);
  input.files = [{size: 268435457}]; await handlers.submit(event); assert.equal(calls, 4);
  input.files = []; await handlers.submit(event); assert.equal(calls, 4);
  console.log('Teacher update UI cancel/retry/double-submit/navigation/error/success tests passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});
