/* User-controlled browser notifications for completed scan findings. */
(function (root) {
  'use strict';
  const preference = 'rt_desktop_alerts_enabled';

  function supported() { return typeof root.Notification === 'function'; }
  function enabled() { return supported() && localStorage.getItem(preference) === 'true'; }
  async function setEnabled(value) {
    if (!value) { localStorage.removeItem(preference); return { enabled: false }; }
    if (!supported()) return { enabled: false, reason: 'Desktop notifications are unavailable in this browser.' };
    const permission = root.Notification.permission === 'default'
      ? await root.Notification.requestPermission() : root.Notification.permission;
    if (permission !== 'granted') return { enabled: false, reason: 'Browser notification permission was not granted.' };
    localStorage.setItem(preference, 'true');
    return { enabled: true };
  }
  function count(report, severity) {
    const value = Number((report.severity_counts || {})[severity]);
    return Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
  }
  function notify(report) {
    if (!enabled()) return false;
    const critical = count(report, 'critical');
    const high = count(report, 'high');
    const urgent = (report.findings || []).filter(f => f && f.exploit_priority === 'urgent').length;
    if (!urgent && !critical && !high) return false;
    const key = `rt_desktop_alerted_${report.scan_id || `${report.target || 'unknown'}_${report.total_time_seconds || 0}`}`;
    if (sessionStorage.getItem(key)) return false;
    sessionStorage.setItem(key, '1');
    const parts = [];
    if (urgent) parts.push(`${urgent} urgent exploit-priority`);
    if (critical) parts.push(`${critical} critical`);
    if (high) parts.push(`${high} high`);
    try {
      new root.Notification('ReconTitan scan alert', {
        body: `${report.target || 'Target'}: ${parts.join(', ')} finding(s) need review.`,
        tag: `recontitan-${report.scan_id || 'scan'}`,
      });
      return true;
    } catch (_) { return false; }
  }
  const api = { supported, enabled, setEnabled, notify };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ReconTitanAlerts = api;
})(typeof window !== 'undefined' ? window : globalThis);
