'use strict';

/* ── Triage ──────────────────────────────────────────────────────────────────
 *
 * Recording that a finding was reviewed, and what was decided.
 *
 * The interface has one job beyond collecting the decision: it must never let
 * suppression feel like deletion. So the reason field is required and says why
 * it is required, the summary banner states how many findings are suppressed
 * whenever any are, and a suppressed finding stays reachable behind a toggle
 * rather than vanishing. A tool that quietly hides findings on request is a
 * tool that can be used to hide findings.
 */

const TRIAGE_STATES = {
  open: {
    label: 'Open',
    note: 'Not yet reviewed. Counts normally.',
    suppresses: false,
  },
  confirmed: {
    label: 'Confirmed real',
    note: 'Reviewed and verified. Still counts, and sorts first.',
    suppresses: false,
  },
  false_positive: {
    label: 'False positive',
    note: 'Reviewed and not real here. Removed from the counts and the attack paths.',
    suppresses: true,
  },
  accepted_risk: {
    label: 'Accepted risk',
    note: 'Real, and the owner has chosen to live with it. Removed from the counts.',
    suppresses: true,
  },
};

const SUPPRESSING_STATES = Object.keys(TRIAGE_STATES).filter(k => TRIAGE_STATES[k].suppresses);

function triageStateOf(finding) {
  const state = finding && finding.triage && finding.triage.state;
  return TRIAGE_STATES[state] ? state : 'open';
}

function isSuppressed(finding) {
  return TRIAGE_STATES[triageStateOf(finding)].suppresses;
}

function createTriageControl(elements, options = {}) {
  const {
    block, buttons, reasonWrap, reasonInput, saveButton, status, current,
  } = elements;
  const save = typeof options.onSave === 'function' ? options.onSave : null;
  let finding = null;
  let selected = 'open';

  function paint() {
    for (const button of buttons) {
      const isCurrent = button.dataset.triageState === selected;
      button.setAttribute('aria-checked', String(isCurrent));
      button.classList.toggle('is-selected', isCurrent);
    }
    // The reason field only appears for the two states that hide something,
    // because those are the only ones that need justifying.
    const needsReason = TRIAGE_STATES[selected].suppresses;
    reasonWrap.hidden = !needsReason;
    status.textContent = TRIAGE_STATES[selected].note;
    status.classList.remove('is-error', 'is-ok');
  }

  function describeExisting() {
    const triage = (finding && finding.triage) || {};
    const state = triageStateOf(finding);
    if (state === 'open') {
      current.textContent = 'No decision recorded yet.';
      return;
    }
    const when = triage.decided_at ? ` on ${triage.decided_at}` : '';
    const why = triage.reason ? ` — “${triage.reason}”` : '';
    current.textContent = `Recorded as ${TRIAGE_STATES[state].label}${when}${why}`;
  }

  function open(nextFinding) {
    finding = nextFinding;
    // A finding with no fingerprint predates triage or came from an older
    // export. Offering a control that cannot save is worse than hiding it.
    const usable = Boolean(finding && finding.triage_fingerprint);
    block.hidden = !usable;
    if (!usable) return;
    selected = triageStateOf(finding);
    reasonInput.value = (finding.triage && finding.triage.reason) || '';
    paint();
    describeExisting();
  }

  for (const button of buttons) {
    button.setAttribute('role', 'radio');
    button.addEventListener('click', () => {
      selected = TRIAGE_STATES[button.dataset.triageState] ? button.dataset.triageState : 'open';
      paint();
      if (TRIAGE_STATES[selected].suppresses) reasonInput.focus();
    });
  }

  saveButton.addEventListener('click', async () => {
    if (!finding || !save) return;
    const reason = reasonInput.value.trim();
    if (TRIAGE_STATES[selected].suppresses && !reason) {
      status.textContent = 'A written reason is required before a finding can be suppressed.';
      status.classList.add('is-error');
      reasonInput.focus();
      return;
    }
    saveButton.disabled = true;
    status.classList.remove('is-error', 'is-ok');
    status.textContent = 'Saving…';
    try {
      await save({
        fingerprint: finding.triage_fingerprint,
        state: selected,
        reason,
      });
      status.textContent = 'Saved.';
      status.classList.add('is-ok');
    } catch (error) {
      status.textContent = String((error && error.message) || error);
      status.classList.add('is-error');
    } finally {
      saveButton.disabled = false;
    }
  });

  return { open };
}

function createTriageSummary(elements) {
  const { root, count, detail, toggle } = elements;
  let revealed = false;
  let onToggle = null;

  toggle.addEventListener('click', () => {
    revealed = !revealed;
    toggle.textContent = revealed ? 'Hide suppressed' : 'Show suppressed';
    toggle.setAttribute('aria-expanded', String(revealed));
    if (onToggle) onToggle(revealed);
  });

  function update(report, handler) {
    onToggle = handler || null;
    const summary = (report && report.triage_summary) || {};
    const total = Number(summary.suppressed_total || 0);
    const confirmed = Number((summary.counts || {}).confirmed || 0);

    if (!total && !confirmed) {
      root.hidden = true;
      return { suppressed: 0, confirmed: 0 };
    }

    const counts = summary.counts || {};
    const parts = [];
    if (counts.false_positive) parts.push(`${counts.false_positive} marked false positive`);
    if (counts.accepted_risk) parts.push(`${counts.accepted_risk} accepted as risk`);
    if (confirmed) parts.push(`${confirmed} confirmed real`);

    count.textContent = total
      ? `${total} finding${total === 1 ? '' : 's'} suppressed by triage`
      : `${confirmed} finding${confirmed === 1 ? '' : 's'} confirmed by review`;
    detail.textContent = parts.length
      ? ` — ${parts.join(', ')}. Suppressed findings are excluded from the counts and the attack paths, and remain in the report and every export.`
      : '';
    toggle.hidden = !total;
    root.hidden = false;
    return { suppressed: total, confirmed };
  }

  return { update, isRevealed: () => revealed };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    TRIAGE_STATES,
    SUPPRESSING_STATES,
    triageStateOf,
    isSuppressed,
    createTriageControl,
    createTriageSummary,
  };
}
