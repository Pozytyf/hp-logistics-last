/* HP LOGISTICS — garde des formulaires (validation côté navigateur + jeton anti-robot).
 * La validation de référence reste celle du serveur (api/forms.php). */
(function () {
  'use strict';
  var ENDPOINT = '/api/forms.php';
  var MIN_WAIT = 3500, token = null, tokenAt = 0, pending = null;

  function lang() { try { return localStorage.getItem('hp-language') === 'en' ? 'en' : 'fr'; } catch (e) { return 'fr'; } }
  var T = {
    fr: { req: 'obligatoire', short: 'trop court', long: 'trop long', email: 'adresse invalide', phone: 'numéro invalide',
          choice: 'valeur non autorisée', net: 'Connexion impossible. Vérifiez votre réseau et réessayez.',
          generic: 'Envoi impossible pour le moment. Contactez-nous par e-mail ou téléphone.',
          labels: { name: 'Nom', email: 'E-mail', phone: 'Téléphone', subject: 'Objet', message: 'Message', goods_type: 'Marchandise',
                    weight: 'Poids', origin: 'Origine', destination: 'Destination', transport_mode: 'Mode de transport', details: 'Détails' } },
    en: { req: 'required', short: 'too short', long: 'too long', email: 'invalid address', phone: 'invalid number',
          choice: 'value not allowed', net: 'Connection failed. Check your network and try again.',
          generic: 'Unable to send right now. Please contact us by email or phone.',
          labels: { name: 'Name', email: 'Email', phone: 'Phone', subject: 'Subject', message: 'Message', goods_type: 'Goods',
                    weight: 'Weight', origin: 'Origin', destination: 'Destination', transport_mode: 'Transport mode', details: 'Details' } }
  };
  var RULES = {
    contact: { name: [2, 100, 1], email: [0, 254, 1], phone: [0, 30, 0], subject: [3, 150, 1], message: [10, 5000, 1] },
    quote: { name: [2, 100, 1], email: [0, 254, 1], phone: [0, 30, 0], goods_type: [2, 200, 1], weight: [1, 50, 0],
             origin: [2, 200, 1], destination: [2, 200, 1], details: [1, 2000, 0], transport_mode: [0, 20, 1] }
  };
  var MODES = ['maritime', 'aerien', 'routier', 'ferroviaire', 'multimodal'];

  function validate(type, d) {
    var t = T[lang()], r = RULES[type], errs = {}, k, v, len, rule;
    for (k in r) {
      rule = r[k]; v = String(d[k] == null ? '' : d[k]).trim(); len = v.length;
      if (!v) { if (rule[2]) errs[k] = t.req; continue; }
      if (len < rule[0]) errs[k] = t.short; else if (len > rule[1]) errs[k] = t.long;
    }
    if (!errs.email && d.email && !/^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]{2,}$/.test(String(d.email).trim())) errs.email = t.email;
    if (!errs.phone && d.phone && String(d.phone).trim()) {
      var p = String(d.phone).trim();
      if (!/^[0-9+().\s-]{6,30}$/.test(p) || (p.match(/\d/g) || []).length < 6) errs.phone = t.phone;
    }
    if (type === 'quote' && !errs.transport_mode && MODES.indexOf(d.transport_mode) < 0) errs.transport_mode = t.choice;
    return errs;
  }
  function summarize(errs) {
    var L = T[lang()].labels, out = [], k;
    for (k in errs) { out.push((L[k] || k) + ' : ' + errs[k]); if (out.length === 3) break; }
    return out.join(' · ');
  }

  function fetchToken() {
    if (pending) return pending;
    pending = fetch(ENDPOINT + '?action=token', { credentials: 'omit', cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (j) { if (j && j.token) { token = j.token; tokenAt = Date.now(); } return token; })
      .catch(function () { return null; })
      .then(function (t) { pending = null; return t; });
    return pending;
  }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  // Le jeton est demandé dès que le visiteur touche un champ d'un de nos formulaires : le délai de remplissage est donc réel.
  document.addEventListener('focusin', function (e) {
    var el = e.target;
    if (!token && el && el.form && el.form.elements && el.form.elements.hp_website) fetchToken();
  }, true);

  function post(type, fields, hp) {
    return fetch(ENDPOINT, {
      method: 'POST', credentials: 'omit', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: type, token: token, lang: lang(), hp_website: hp, fields: fields })
    }).then(function (r) { return r.json().catch(function () { return {}; }); });
  }

  function submit(type, fields, form) {
    var t = T[lang()], errs = validate(type, fields), hp = '';
    if (Object.keys(errs).length) {
      try { var first = Object.keys(errs)[0]; if (form && form.elements && form.elements[first]) form.elements[first].focus(); } catch (e) {}
      return Promise.resolve({ error: { message: summarize(errs) } });
    }
    try { hp = (form && form.elements && form.elements.hp_website) ? form.elements.hp_website.value : ''; } catch (e) {}
    var retried = false;
    function attempt() {
      var ready = (token && Date.now() - tokenAt < 7000000) ? Promise.resolve(token) : fetchToken();
      return ready.then(function () {
        var wait = MIN_WAIT - (Date.now() - tokenAt);
        return wait > 0 ? sleep(wait) : null;
      }).then(function () {
        if (!token) return { error: { message: t.net } };
        return post(type, fields, hp).then(function (j) {
          if (j && j.ok) return { error: null };
          if (!retried && j && (j.code === 'token' || j.code === 'expired' || j.code === 'too_fast')) {
            retried = true; token = null; return attempt();
          }
          var msg = (j && j.fields) ? summarize(j.fields) : (j && j.message) || t.generic;
          return { error: { message: msg } };
        });
      }).catch(function () { return { error: { message: t.net } }; });
    }
    return attempt();
  }

  try { Object.defineProperty(window, '__hpForms', { value: Object.freeze({ submit: submit }), writable: false }); } catch (e) {}
})();
