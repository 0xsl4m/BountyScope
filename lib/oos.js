// BountyScope — always out-of-scope domains (ad/tracking/analytics infrastructure).
// Applies on top of the user's target scope, for capture AND active scanning.
export const BASE_OOS = [
  // Ad networks
  'doubleclick.net', 'googlesyndication.com', '2mdn.net', 'googletagservices.com',
  'googleadservices.com', 'flashtalking.com', 'adtrafficquality.google', 'moatads.com',
  // Tag managers / analytics
  'googletagmanager.com', 'google-analytics.com', 'qualtrics.com', 'tiqcdn.com',
  'tealiumiq.com', 'tealium.com', 'segment.com', 'segmentapis.com', 'mixpanel.com',
  'hotjar.com', 'fullstory.com', 'heap.io', 'amplitude.com', 'braze.com',
  'adobedtm.com', 'cookielaw.org', 'demdex.net', 'omtrdc.net', 'adobedc.net',
  // Popup / engagement widgets
  'bounceexchange.com', 'bouncex.net',
  // Social
  'facebook.net', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
  'youtube.com', 'ytimg.com', 'twimg.com',
  // CDN / fonts / libs
  'fastly.net', 'cloudflare.com', 'jquery.com', 'jsdelivr.net', 'unpkg.com',
  'typekit.net', 'fonts.googleapis.com', 'fonts.gstatic.com',
  // 3rd-party content widgets
  'usestoryteller.com', 'storyteller.com',
];
