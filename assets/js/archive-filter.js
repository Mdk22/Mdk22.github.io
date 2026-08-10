(() => {
  const root = document.querySelector('[data-archive-filter]');
  const results = document.querySelector('[data-archive-results]');
  if (!root || !results) return;

  const cards = Array.from(results.querySelectorAll('[data-archive-card]'));
  const search = root.querySelector('[data-archive-search]');
  const cwe = root.querySelector('[data-archive-cwe]');
  const evidence = root.querySelector('[data-archive-evidence]');
  const familyButtons = Array.from(root.querySelectorAll('[data-archive-family]'));
  const count = document.querySelector('[data-archive-count]');
  const empty = document.querySelector('[data-archive-empty]');
  let family = '';

  const update = () => {
    const query = (search.value || '').trim().toLowerCase();
    const visible = cards.filter((card) => {
      const matchesQuery = !query || card.dataset.search.includes(query);
      const matchesFamily = !family || card.dataset.family === family;
      const matchesCwe = !cwe.value || card.dataset.cwe === cwe.value;
      const matchesEvidence = !evidence.value || card.dataset.evidence.split('|').includes(evidence.value);
      const match = matchesQuery && matchesFamily && matchesCwe && matchesEvidence;
      card.hidden = !match;
      return match;
    });

    if (count) count.textContent = `${String(visible.length).padStart(2, '0')} records`;
    empty.hidden = visible.length !== 0;
  };

  search.addEventListener('input', update);
  cwe.addEventListener('change', update);
  evidence.addEventListener('change', update);
  familyButtons.forEach((button) => {
    button.addEventListener('click', () => {
      family = button.dataset.archiveFamily || '';
      familyButtons.forEach((item) => item.setAttribute('aria-pressed', String(item === button)));
      update();
    });
  });
})();
