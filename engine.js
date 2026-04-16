// Shield — Scam Detection Engine
// Threshold Interactive Studios
// Rule-based, fully local, no API required

const RULES = {

  urgency: {
    weight: 25,
    patterns: [
      /act\s*(now|immediately|today|fast|quick)/i,
      /urgent(ly)?(\s+action)?(\s+required)?/i,
      /expires?\s+(in\s+)?\d+\s*(hour|minute|day)/i,
      /limited\s+time/i,
      /respond\s+(within|by|before)/i,
      /last\s+(chance|warning|notice|opportunity)/i,
      /don'?t\s+(delay|wait|ignore)/i,
      /time\s+(is\s+)?(running|sensitive)/i,
      /immediate(ly)?\s+(action|response|attention)/i,
      /within\s+(24|48|72)\s*hours?/i,
      /deadline/i,
      /final\s+(notice|warning|demand|reminder)/i,
      /must\s+(respond|act|call|verify|confirm)\s+(now|immediately|today)/i,
      /before\s+(it'?s?\s+too\s+late|midnight|end\s+of\s+day)/i,
      /only\s+\d+\s+(spots?|slots?|left|remaining)/i,
    ]
  },

  authority: {
    weight: 35,
    patterns: [
      /\b(irs|internal\s+revenue)\b/i,
      /\b(social\s+security(\s+administration)?|ssa)\b/i,
      /\b(medicare|medicaid)\b/i,
      /\b(fbi|federal\s+bureau)\b/i,
      /\b(cia|homeland\s+security|dhs)\b/i,
      /\b(department\s+of\s+(justice|treasury|labor))\b/i,
      /\b(microsoft\s+(support|security|helpdesk))\b/i,
      /\b(apple\s+(support|security|care))\b/i,
      /\b(amazon\s+(support|security|prime|account))\b/i,
      /\b(paypal\s+(support|security|team))\b/i,
      /\b(bank\s+of\s+america|chase\s+bank|wells\s+fargo|citibank)\b/i,
      /\b(visa|mastercard)\s+(security|fraud|team)/i,
      /\b(google\s+(account|security|support|team))\b/i,
      /\b(windows\s+(support|security|defender|team))\b/i,
      /\b(tech(nical)?\s+support)\b/i,
      /your\s+(bank|account|card)\s+(has\s+been|was)/i,
      /law\s+enforcement/i,
      /official\s+(notice|notification|warning)/i,
      /\b(usps|fedex|ups|dhl)\s+(delivery|package|parcel|notice)/i,
      /customs\s+(and\s+border|clearance|hold)/i,
      /\b(coinbase|binance|kraken)\s+(support|security|team)/i,
      /\b(cash\s*app|venmo|zelle)\s+(support|team|security)/i,
      /account\s+review\s+team/i,
      /fraud\s+(prevention|department|team)/i,
    ]
  },

  threat: {
    weight: 40,
    patterns: [
      /\b(arrest(ed)?|warrant)\b/i,
      /criminal\s+(charge|investigation|record)/i,
      /legal\s+(action|proceeding)/i,
      /suspend(ed)?\s+(account|access|service)/i,
      /terminat(ed?|ion)\s+(account|access|service)/i,
      /blocked\s+(account|card|access)/i,
      /compromised\s+(account|password|security)/i,
      /unauthorized\s+(access|activity|login|charge)/i,
      /suspicious\s+(activity|login|transaction)/i,
      /account\s+(has\s+been\s+)?(hacked|breached|compromised)/i,
      /deport(ed|ation)/i,
      /lawsuit/i,
      /frozen\s+(account|funds|assets)/i,
      /virus\s+(detected|found|infected)/i,
      /hacker(s)?\s+(have|has|gained)/i,
      /your\s+(computer|device|pc)\s+(is|has\s+been)\s+(infected|hacked|compromised)/i,
      /permanently\s+(suspended|banned|closed|deleted)/i,
      /face\s+(charges|arrest|prosecution)/i,
      /turned\s+over\s+to\s+(authorities|law\s+enforcement)/i,
    ]
  },

  reward: {
    weight: 20,
    patterns: [
      /you\s+(have\s+)?(won|been\s+selected|are\s+a\s+winner)/i,
      /congratulations.{0,30}(won|winner|prize|award)/i,
      /claim\s+(your\s+)?(prize|reward|gift|money|cash)/i,
      /free\s+(gift|money|cash|iphone|laptop|vacation)/i,
      /\$\d+[\d,]*\s*(gift\s+card|reward|prize|cash)/i,
      /lottery|sweepstake/i,
      /unclaimed\s+(funds|money|package|prize)/i,
      /inheritance/i,
      /you\s+have\s+a\s+(package|parcel|delivery)\s+(waiting|pending|held)/i,
      /refund\s+(is\s+)?(waiting|pending|available|owed)/i,
      /you\s+(received|got)\s+a\s+(payment|transfer|deposit)/i,
      /click\s+to\s+(claim|receive|collect)\s+your/i,
      /bonus\s+(payment|deposit|transfer)/i,
      /government\s+(grant|check|payment|stimulus)/i,
    ]
  },

  payment: {
    weight: 45,
    patterns: [
      /gift\s+card(s)?\s+(number|code|pin)/i,
      /buy\s+(itunes|google\s+play|amazon|steam)\s+(gift\s+)?card/i,
      /wire\s+transfer/i,
      /western\s+union|money\s+gram/i,
      /bitcoin|crypto(currency)?|ethereum|usdt|tether/i,
      /send\s+(money|cash|payment|funds)/i,
      /pay\s+(with\s+)?(gift\s+card|bitcoin|crypto|wire)/i,
      /zelle|cashapp|venmo.{0,20}(send|pay|transfer)/i,
      /provide\s+(your\s+)?(credit|debit)\s+card/i,
      /processing\s+fee/i,
      /advance\s+fee/i,
      /small\s+(fee|deposit|payment)\s+(to\s+)?(release|unlock|claim)/i,
      /investment\s+(opportunity|platform|returns?)/i,
      /guaranteed\s+(return|profit|income)/i,
      /double\s+your\s+(money|investment|bitcoin)/i,
      /weekly\s+(returns?|profit|income)\s+of\s+\d+%/i,
    ]
  },

  credential: {
    weight: 40,
    patterns: [
      /verify\s+(your\s+)?(account|identity|information|password|ssn|social)/i,
      /confirm\s+(your\s+)?(account|identity|information|password|details)/i,
      /update\s+(your\s+)?(account|payment|billing|information|details)/i,
      /enter\s+(your\s+)?(password|pin|ssn|social\s+security|credit\s+card)/i,
      /provide\s+(your\s+)?(ssn|social\s+security|date\s+of\s+birth|mother)/i,
      /click\s+(here|below|link)\s+to\s+(verify|confirm|update|login|access)/i,
      /log\s*(in|on)\s+(to\s+)?(verify|confirm|secure|protect)/i,
      /your\s+(ssn|social\s+security\s+number)/i,
      /mother'?s\s+maiden\s+name/i,
      /security\s+(question|code|pin|number)/i,
      /one.?time\s+(code|password|pin)/i,
      /two.?factor|2fa\s+code/i,
      /remote\s+(access|desktop|control)/i,
      /download\s+(this\s+)?(app|software|tool)\s+(to\s+)?(fix|resolve|secure)/i,
      /recovery\s+(phrase|seed|words?)/i,
      /private\s+key/i,
      /share\s+(your\s+)?(screen|desktop)/i,
    ]
  },

  phishing: {
    weight: 35,
    patterns: [
      /https?:\/\/[^\s]*\.(xyz|tk|ml|ga|cf|gq|top|club|online|site|website|space)\b/i,
      /https?:\/\/[^\s]*(paypa1|paypai|amaz0n|arnazon|micros0ft|g00gle|app1e|netf1ix)[^\s]*/i,
      /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
      /https?:\/\/[^\s]*-(login|secure|verify|update|account|support)[^\s]*/i,
      /https?:\/\/[^\s]*(login|secure|verify|update|account)-[^\s]*/i,
      /bit\.ly|tinyurl|t\.co|ow\.ly|goo\.gl/i,
      /https?:\/\/[^\s]{0,15}\.(ru|cn|br|ng|pk)\//i,
      /https?:\/\/[^\s]*(wallet|crypto|defi|nft)[^\s]*(connect|verify|sync)[^\s]*/i,
    ]
  },

  isolation: {
    weight: 30,
    patterns: [
      /don'?t\s+(tell|inform|contact|call)\s+(anyone|your\s+(family|spouse|bank|lawyer))/i,
      /keep\s+(this\s+)?(confidential|secret|between\s+us)/i,
      /do\s+not\s+(share|discuss|mention)\s+(this|our\s+conversation)/i,
      /your\s+(family|spouse|friends)\s+(wouldn'?t|won'?t|don'?t)\s+understand/i,
      /this\s+is\s+(strictly\s+)?confidential/i,
      /between\s+(you\s+and\s+me|us\s+only)/i,
      /do\s+not\s+contact\s+(your\s+)?(local\s+)?(branch|bank|police)/i,
      /handled\s+exclusively\s+by/i,
    ]
  },

  romance_pig: {
    weight: 30,
    patterns: [
      /i\s+(found|met)\s+you\s+(on|through)\s+(facebook|instagram|tinder|hinge)/i,
      /i\s+(am|'m)\s+a\s+(doctor|nurse|engineer|soldier|military)\s+(working|deployed|stationed)/i,
      /my\s+(late|deceased)\s+(wife|husband|spouse)/i,
      /i\s+(want|would\s+like)\s+to\s+(know|meet)\s+you\s+better/i,
      /trading\s+platform.{0,30}(profit|return|investment)/i,
      /my\s+(uncle|friend|mentor)\s+taught\s+me\s+(how\s+to\s+trade|this\s+method)/i,
      /small\s+investment.{0,30}big\s+(return|profit)/i,
      /i\s+can\s+(show|teach|help)\s+you\s+(how\s+to\s+)?(make|earn|invest)/i,
    ]
  },

  job_scam: {
    weight: 35,
    patterns: [
      /work\s+from\s+home.{0,30}(per\s+(day|week|hour)|\$\d+)/i,
      /no\s+experience\s+(required|needed|necessary)/i,
      /earn\s+\$\d+[\d,]*\s*(per\s+)?(day|week|hour)\s+(from\s+home|online|working)/i,
      /just\s+(need|provide)\s+your\s+(ssn|social|banking|direct\s+deposit)/i,
      /we\s+(will\s+)?(send|mail|deposit)\s+(you\s+)?(a\s+)?check/i,
      /mystery\s+shopper/i,
      /reshipping|re-shipping/i,
      /package\s+(forwarding|reshipping)\s+(job|opportunity|position)/i,
      /paid\s+(training|onboarding)\s+(check|advance)/i,
    ]
  },

  grandparent: {
    weight: 40,
    patterns: [
      /grandma|grandpa|nana|papa.{0,20}(help|trouble|jail|arrested|accident)/i,
      /it'?s\s+(me|your).{0,20}(don'?t\s+tell|please\s+don'?t\s+tell)/i,
      /i'?m\s+in\s+(trouble|jail|the\s+hospital|an\s+accident)/i,
      /bail\s+(money|bond|cash)/i,
      /please\s+(don'?t\s+tell|keep\s+this\s+from)\s+(mom|dad|your\s+(son|daughter|family))/i,
      /i\s+need\s+(cash|money|help)\s+(right\s+now|immediately|today)\s+(please|badly)/i,
    ]
  },

  crypto_recovery: {
    weight: 45,
    patterns: [
      /recover\s+(your\s+)?(lost|stolen)\s+(crypto|bitcoin|funds|money)/i,
      /crypto\s+recovery\s+(expert|specialist|service)/i,
      /i\s+(was\s+)?(scammed|lost)\s+(and\s+)?(recovered|got\s+back)\s+my/i,
      /blockchain\s+(recovery|retrieval|expert)/i,
      /hack(ed)?\s+(wallet|account|exchange).{0,30}(recover|retrieve|get\s+back)/i,
      /contact\s+(this\s+)?(expert|specialist|hacker)\s+to\s+recover/i,
    ]
  }
};


// Brand impersonation — checks if text claims to be from a known brand
// but doesn't come from their actual domain
const BRAND_DOMAINS = {
  'paypal': ['paypal.com'],
  'amazon': ['amazon.com', 'amazon.co.uk'],
  'apple': ['apple.com', 'icloud.com'],
  'microsoft': ['microsoft.com', 'outlook.com', 'live.com'],
  'google': ['google.com', 'gmail.com'],
  'netflix': ['netflix.com'],
  'chase': ['chase.com'],
  'bankofamerica': ['bankofamerica.com'],
  'wellsfargo': ['wellsfargo.com'],
  'irs': ['irs.gov'],
  'socialsecurity': ['ssa.gov'],
  'medicare': ['medicare.gov'],
};

function analyzeText(text) {
  if (!text || text.trim().length < 10) return null;

  const result = {
    text: text.substring(0, 500),
    score: 0,
    risk: 'safe',
    categories: [],
    reasons: [],
    timestamp: Date.now()
  };

  // Run all rule categories
  for (const [category, config] of Object.entries(RULES)) {
    const matches = [];
    for (const pattern of config.patterns) {
      const match = text.match(pattern);
      if (match) matches.push(match[0]);
    }
    if (matches.length > 0) {
      const catScore = config.weight * Math.min(matches.length, 3);
      result.score += catScore;
      result.categories.push(category);
      result.reasons.push({
        category,
        matches: matches.slice(0, 3),
        weight: catScore
      });
    }
  }

  // Compound scoring — multiple categories = more suspicious
  if (result.categories.length >= 3) result.score *= 1.4;
  if (result.categories.length >= 4) result.score *= 1.2;

  // Determine risk level
  if (result.score >= 120) result.risk = 'critical';
  else if (result.score >= 70) result.risk = 'high';
  else if (result.score >= 35) result.risk = 'medium';
  else if (result.score >= 15) result.risk = 'low';
  else result.risk = 'safe';

  if (result.risk === 'safe') return null;
  return result;
}

// Category display names
const CATEGORY_LABELS = {
  urgency: 'Creates urgency',
  authority: 'Impersonates authority',
  threat: 'Uses threats',
  reward: 'Promises reward',
  payment: 'Requests unusual payment',
  credential: 'Requests credentials or access',
  phishing: 'Suspicious links',
  isolation: 'Asks you to keep secret'
};

const RISK_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#84cc16',
  safe: '#22c55e'
};

const RISK_LABELS = {
  critical: 'CRITICAL — Very likely a scam',
  high: 'HIGH RISK — Strong scam indicators',
  medium: 'MEDIUM RISK — Suspicious content',
  low: 'LOW RISK — Some suspicious patterns',
  safe: 'Safe'
};

module.exports = { analyzeText, CATEGORY_LABELS, RISK_COLORS, RISK_LABELS };
