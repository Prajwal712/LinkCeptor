/**
 * Smart Link Interceptor — Whitelist
 * 
 * Top-level safe domains that bypass server verification entirely.
 * This eliminates latency and API costs for standard browsing.
 */

const SAFE_DOMAINS = new Set([
  // Search & General
  'google.com', 'google.co.in', 'bing.com', 'duckduckgo.com', 'yahoo.com',

  // Social & Communication
  'facebook.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com',
  'reddit.com', 'discord.com', 'telegram.org', 'whatsapp.com',

  // Email
  'gmail.com', 'outlook.com', 'outlook.live.com', 'mail.google.com',

  // Development
  'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
  'npmjs.com', 'pypi.org', 'crates.io', 'hub.docker.com',

  // Cloud & Services
  'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',
  'vercel.com', 'netlify.com', 'heroku.com', 'render.com',

  // Commerce & Finance
  'amazon.com', 'amazon.in', 'flipkart.com', 'paypal.com', 'stripe.com',
  'razorpay.com',

  // Media & Content
  'youtube.com', 'netflix.com', 'spotify.com', 'medium.com', 'notion.so',
  'figma.com', 'canva.com',

  // Knowledge
  'wikipedia.org', 'wikimedia.org', 'archive.org',

  // Microsoft
  'microsoft.com', 'office.com', 'live.com', 'onedrive.com',

  // Apple
  'apple.com', 'icloud.com',

  // Education
  'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
]);


function extractRootDomain(url) {
  try {
    const hostname = new URL(url).hostname;
    const parts = hostname.split('.');
    // Handle co.in, co.uk, etc.
    if (parts.length >= 3 && parts[parts.length - 2].length <= 3) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  } catch {
    return null;
  }
}

/**
 * Returns true if the URL belongs to a known safe domain
 */
function isWhitelisted(url) {
  const domain = extractRootDomain(url);
  return domain ? SAFE_DOMAINS.has(domain) : false;
}
