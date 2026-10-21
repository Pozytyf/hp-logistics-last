<?php
/**
 * HP LOGISTICS — configuration du endpoint formulaires (api/forms.php)
 *
 * Ce fichier ne contient AUCUN secret. Les valeurs sensibles (clé service Supabase,
 * secret HMAC personnalisé) se mettent dans api/config.local.php, à créer sur le
 * serveur LWS (voir api/config.local.php.example) et à ne jamais publier.
 */
if (!defined('HP_FORMS')) { http_response_code(404); exit; }

$cfg = array(
    // Domaines autorisés à appeler le endpoint (contrôle Origin / Referer)
    'allowed_hosts' => array('hp-logistics.net', 'www.hp-logistics.net'),

    // Notification e-mail (utilise mail() de LWS ; l'expéditeur DOIT être une adresse du domaine)
    'mail_enabled'  => true,
    'notify_to'     => 'info@hp-logistics.net',
    'mail_from'     => 'no-reply@hp-logistics.net',

    // Enregistrement dans la base du site (tableau de bord admin : messages / devis).
    // L'URL et la clé "publishable" sont publiques par conception (déjà présentes dans le site).
    'supabase_url'         => 'https://c--662a420a-43c9-4595-8e3c-a67ad84f3a69-prod.lovable.cloud',
    'supabase_key'         => 'sb_publishable_aaZzIBk61M3aRms04dTpvw_EYPoUDE9',
    'supabase_service_key' => '', // à renseigner UNIQUEMENT dans config.local.php

    // Dernier filet de sécurité : copie JSON dans api/_data/outbox (dossier interdit d'accès web)
    'outbox_enabled' => true,

    // Anti-spam
    'min_fill_seconds' => 3,        // délai minimum entre l'ouverture du formulaire et l'envoi
    'max_token_age'    => 7200,     // validité du jeton (2 h)
    'max_links'        => 2,        // au-delà : considéré comme spam
    'rate_attempts'    => array(40, 600),   // [max, fenêtre en s] toutes requêtes POST / IP
    'rate_send_10min'  => array(5, 600),    // envois acceptés / IP / 10 min
    'rate_send_day'    => array(20, 86400), // envois acceptés / IP / 24 h
    'rate_global_day'  => array(300, 86400),// envois acceptés, tous visiteurs / 24 h

    // N'activer que si le site est derrière un proxy de confiance qui pose X-Forwarded-For
    'trust_proxy_headers' => false,

    // Secret HMAC : si vide, généré automatiquement dans api/_data/secret.key
    'secret'   => '',
    'data_dir' => dirname(__FILE__) . '/_data',
);

$local = dirname(__FILE__) . '/config.local.php';
if (is_file($local)) {
    $over = require $local;
    if (is_array($over)) { $cfg = array_merge($cfg, $over); }
}
return $cfg;
