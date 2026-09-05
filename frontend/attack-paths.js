'use strict';

/* ── Attack paths view ───────────────────────────────────────────────────────
 *
 * Renders the chains the backend correlated: how an attacker reaches the
 * target, what they pass through, and what the scanner actually proved along
 * the way.
 *
 * The whole point of this view is the distinction between three claims, so the
 * rendering never flattens them:
 *
 *   confirmed  observed or safely proven on THIS target
 *   supported  several observations agree, or an authoritative source does
 *   possible   a plausible next step that was never executed
 *
 * A path made of confirmed steps that ends in a possible one is not an
 * exploited host, and this view has to keep saying so. Every step carries its
 * level as a visible label, not only as a colour.
 */

const PATH_STATUS = {
  exploited: {
    label: 'Confirmed on this target',
    note: 'The scanner executed a bounded proof and recorded the result.',
    tone: 'critical',
  },
  version_confirmed: {
    label: 'Version-confirmed',
    note: 'The detected version falls inside the vulnerable range. No exploit was run.',
    tone: 'high',
  },
  supported: {
    label: 'Supported by evidence',
    note: 'Several observations agree, but the chain was not executed end to end.',
    tone: 'medium',
  },
  candidate: {
    label: 'Candidate',
    note: 'A plausible route that needs manual validation before it is believed.',
    tone: 'low',
  },
  blocked: {
    label: 'Blocked',
    note: 'The scanner tested this route and a control stopped it. Kept because the control is what is holding.',
    tone: 'info',
  },
};

const LEVEL_LABEL = {
  confirmed: 'confirmed',
  supported: 'supported',
  possible: 'possible',
};

const STEP_ROLE = {
  target: 'Entry point',
  service: 'Exposed service',
  endpoint: 'Reachable endpoint',
  input: 'Attacker-controlled input',
  payload: 'Payload tested',
  software: 'Software identified',
  cve: 'Known vulnerability',
  threat: 'Threat intelligence',
  technique: 'Technique',
  proof: 'Proof captured',
  control: 'Control that stopped it',
};

function pathsEscape(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function createAttackPathsView(root, options = {}) {
  const list = root.querySelector('[data-paths-list]');
  const summary = root.querySelector('[data-paths-summary]');
  const legend = root.querySelector('[data-paths-legend]');
  const onOpenFinding = typeof options.onOpenFinding === 'function' ? options.onOpenFinding : null;
  let paths = [];

  function renderStep(step, index, total) {
    const level = LEVEL_LABEL[step.evidence_level] || 'possible';
    const role = STEP_ROLE[step.kind] || 'Step';
    const clickable = step.source_finding_id && onOpenFinding;
    return `
      <li class="path-step level-${level}${clickable ? ' is-clickable' : ''}"
          ${clickable ? `data-finding-id="${pathsEscape(step.source_finding_id)}" tabindex="0" role="button"` : ''}>
        <span class="path-step-marker" aria-hidden="true">${index + 1}</span>
        <div class="path-step-body">
          <div class="path-step-head">
            <span class="path-step-role">${pathsEscape(role)}</span>
            <span class="path-level level-${level}">${pathsEscape(level)}</span>
          </div>
          <div class="path-step-label">${pathsEscape(step.label)}</div>
          ${step.detail ? `<p class="path-step-detail">${pathsEscape(step.detail)}</p>` : ''}
        </div>
        ${index < total - 1 ? '<span class="path-connector" aria-hidden="true"></span>' : ''}
      </li>`;
  }

  function renderPath(path) {
    const status = PATH_STATUS[path.status] || PATH_STATUS.candidate;
    const steps = (path.steps || []);
    // Say the weakest link out loud. A reader scanning quickly should not have
    // to audit seven steps to notice the last one was never executed.
    const weakest = steps.some(s => s.evidence_level === 'possible') ? 'possible'
      : steps.some(s => s.evidence_level === 'supported') ? 'supported'
      : 'confirmed';
    const chainNote = weakest === 'confirmed'
      ? 'Every step in this chain was observed or proven.'
      : weakest === 'supported'
        ? 'The chain holds up to a supported step; it was not executed end to end.'
        : 'The chain ends in a step that was never executed. Treat the outcome as unproven.';

    const impacts = (path.possible_impacts || []);
    return `
      <article class="attack-path tone-${status.tone}" data-path-id="${pathsEscape(path.id)}">
        <header class="attack-path-head">
          <div class="attack-path-titles">
            <h3>${pathsEscape(path.title)}</h3>
            <p class="attack-path-type">${pathsEscape(path.attack_type || '')}</p>
          </div>
          <div class="attack-path-badges">
            <span class="path-status tone-${status.tone}">${pathsEscape(status.label)}</span>
            <span class="path-sev sev-${pathsEscape(path.severity)}">${pathsEscape(String(path.severity).toUpperCase())}</span>
          </div>
        </header>
        <p class="attack-path-note">${pathsEscape(status.note)}</p>
        <ol class="path-steps">${steps.map((s, i) => renderStep(s, i, steps.length)).join('')}</ol>
        <p class="attack-path-chain level-${weakest}">${pathsEscape(chainNote)}</p>
        ${impacts.length ? `
        <div class="attack-path-block">
          <div class="attack-path-lbl">${path.attack_confirmed ? 'Demonstrated impact' : 'Possible impact if exploited'}</div>
          <ul class="path-impacts">${impacts.map(i => `<li>${pathsEscape(i)}</li>`).join('')}</ul>
        </div>` : ''}
        ${path.remediation ? `
        <div class="attack-path-block">
          <div class="attack-path-lbl">Break the chain here</div>
          <p class="path-remediation">${pathsEscape(path.remediation)}</p>
        </div>` : ''}
      </article>`;
  }

  function update(report) {
    paths = Array.isArray(report && report.attack_paths) ? report.attack_paths : [];
    if (!paths.length) {
      root.hidden = true;
      return { count: 0 };
    }

    const counts = paths.reduce((acc, p) => { acc[p.status] = (acc[p.status] || 0) + 1; return acc; }, {});
    const parts = [];
    if (counts.exploited) parts.push(`${counts.exploited} confirmed on this target`);
    if (counts.version_confirmed) parts.push(`${counts.version_confirmed} version-confirmed`);
    if (counts.supported) parts.push(`${counts.supported} supported`);
    if (counts.candidate) parts.push(`${counts.candidate} candidate`);
    if (counts.blocked) parts.push(`${counts.blocked} blocked`);
    summary.textContent = `${paths.length} path${paths.length === 1 ? '' : 's'} · ${parts.join(' · ')}`;

    if (legend) {
      legend.innerHTML = `
        <span class="path-level level-confirmed">confirmed</span> observed or proven here
        <span class="path-level level-supported">supported</span> evidence agrees, not executed
        <span class="path-level level-possible">possible</span> never executed`;
    }

    list.innerHTML = paths.map(renderPath).join('');
    root.hidden = false;
    return { count: paths.length };
  }

  // Clicking a step opens the finding it came from, so every claim in this
  // view is one click from the evidence that produced it.
  function openFrom(element) {
    const step = element.closest('[data-finding-id]');
    if (step && onOpenFinding) onOpenFinding(step.dataset.findingId);
  }
  root.addEventListener('click', event => openFrom(event.target));
  root.addEventListener('keydown', event => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    if (!event.target.closest('[data-finding-id]')) return;
    event.preventDefault();
    openFrom(event.target);
  });

  return { update };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { createAttackPathsView, PATH_STATUS, STEP_ROLE };
}
