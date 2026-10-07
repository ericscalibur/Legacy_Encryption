// ==== BEGIN LEGACY CORE ====
// Legacy Encryption core — the one and only implementation of the format.
//
// This block is the single source of truth for the JavaScript crypto. It is
// copied byte-for-byte into Legacy-offline.html, encrypt.html and
// decrypt.html by `node tools/sync-core.js`, and the test suite fails if any
// copy drifts. Edit legacy-core.js, then re-run the sync script.
//
// Format (see PROTOCOL-SPEC.md for the full, implementer-facing spec):
//
//   payload    = base64url(salt(16) || iv(12) || ciphertext)       (no '=')
//   password   = canon(benefactorKey) || 0x1F || canon(beneficiaryKey)
//   key        = PBKDF2-HMAC-SHA256(password, salt, 600000, 32 bytes)
//   plaintext  = padLen(1) || seed || padBytes(padLen)              padLen 0..4
//   ciphertext = AES-256-GCM(key, iv, plaintext), 16-byte tag appended, no AAD
//
// Every visible byte is random (salt, IV, ciphertext), so a payload carries
// no marker identifying it as Legacy. All parameters are fixed by the
// format; nothing about them is stored.
//
// The seed is the canonical mnemonic: lowercase BIP-39 English words joined
// by single spaces. canon() is defined in canonicalizeKey() below; it is part
// of the format, and every implementation must apply it identically.
//
// Pure functions only: no DOM access. Runs in browsers and in Node (>= 19).
var LegacyCore = (function () {
    "use strict";

    const ITERATIONS = 600000;
    const SALT_LEN = 16;
    const IV_LEN = 12;
    const TAG_LEN = 16;
    const MAX_PAD = 4;
    // Shortest and longest canonical mnemonics: 12 three-letter words
    // (47 bytes) and 24 eight-letter words (215 bytes).
    const MIN_SEED_LEN = 47;
    const MAX_SEED_LEN = 215;
    const MIN_BODY = SALT_LEN + IV_LEN + 1 + MIN_SEED_LEN + TAG_LEN;           // 92
    const MAX_BODY = SALT_LEN + IV_LEN + 1 + MAX_SEED_LEN + MAX_PAD + TAG_LEN; // 264
    const KEY_SEPARATOR = 0x1f;

    // Official BIP-39 English wordlist (sha256 of english.txt:
    // 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda).
    const WORDLIST = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
        "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
        "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
        "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
        "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
        "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
        "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
        "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
        "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
        "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
        "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
        "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
        "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
        "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
        "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
        "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
        "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
        "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
        "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
        "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
        "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
        "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
        "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
        "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
        "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
        "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
        "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
        "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
        "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
        "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
        "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable",
        "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
        "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
        "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling",
        "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
        "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap",
        "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
        "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar",
        "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
        "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff",
        "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud",
        "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
        "code", "coffee", "coil", "coin", "collect", "color", "column", "combine",
        "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm",
        "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper",
        "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch",
        "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
        "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream",
        "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
        "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch",
        "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious",
        "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
        "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn",
        "day", "deal", "debate", "debris", "decade", "december", "decide", "decline",
        "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
        "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend",
        "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
        "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram",
        "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital",
        "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
        "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide",
        "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
        "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
        "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill",
        "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb",
        "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager",
        "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
        "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight",
        "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator",
        "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ",
        "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy",
        "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
        "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode",
        "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt",
        "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
        "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude",
        "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
        "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend",
        "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint",
        "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy",
        "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault",
        "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
        "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field",
        "figure", "file", "film", "filter", "final", "find", "fine", "finger",
        "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness",
        "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight",
        "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly",
        "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot",
        "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil",
        "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend",
        "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel",
        "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy",
        "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment",
        "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius",
        "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
        "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass",
        "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
        "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip",
        "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass",
        "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group",
        "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun",
        "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
        "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard",
        "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet",
        "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip",
        "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow",
        "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital",
        "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble",
        "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband",
        "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill",
        "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose",
        "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate",
        "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial",
        "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
        "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest",
        "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory",
        "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
        "job", "join", "joke", "journey", "joy", "judge", "juice", "jump",
        "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
        "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit",
        "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know",
        "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language",
        "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
        "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
        "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend",
        "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty",
        "library", "license", "life", "lift", "light", "like", "limb", "limit",
        "link", "lion", "liquid", "list", "little", "live", "lizard", "load",
        "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop",
        "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber",
        "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
        "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
        "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin",
        "marine", "market", "marriage", "mask", "mass", "master", "match", "material",
        "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure",
        "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory",
        "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
        "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
        "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake",
        "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment",
        "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
        "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie",
        "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
        "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
        "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative",
        "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
        "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
        "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice",
        "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey",
        "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
        "october", "odor", "off", "offer", "office", "often", "oil", "okay",
        "old", "olive", "olympic", "omit", "once", "one", "onion", "online",
        "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
        "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
        "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
        "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page",
        "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper",
        "parade", "parent", "park", "parrot", "party", "pass", "patch", "path",
        "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut",
        "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper",
        "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
        "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot",
        "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet",
        "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge",
        "poem", "poet", "point", "polar", "pole", "police", "pond", "pony",
        "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery",
        "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
        "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
        "prison", "private", "prize", "problem", "process", "produce", "profit", "program",
        "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide",
        "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
        "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle",
        "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz",
        "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail",
        "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid",
        "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real",
        "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
        "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject",
        "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
        "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report",
        "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire",
        "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
        "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid",
        "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road",
        "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room",
        "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude",
        "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness",
        "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same",
        "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
        "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science",
        "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea",
        "search", "season", "seat", "second", "secret", "section", "security", "seed",
        "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
        "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
        "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
        "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
        "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
        "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
        "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
        "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab",
        "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan",
        "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth",
        "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
        "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
        "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
        "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
        "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
        "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray",
        "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
        "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay",
        "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting",
        "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
        "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
        "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
        "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme",
        "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
        "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
        "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
        "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
        "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten",
        "tenant", "tennis", "tent", "term", "test", "text", "thank", "that",
        "theme", "then", "theory", "there", "they", "thing", "this", "thought",
        "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger",
        "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title",
        "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
        "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top",
        "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist",
        "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
        "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
        "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy",
        "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try",
        "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
        "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
        "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
        "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown",
        "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon",
        "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
        "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley",
        "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
        "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very",
        "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view",
        "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual",
        "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote",
        "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want",
        "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
        "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding",
        "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat",
        "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife",
        "wild", "will", "win", "window", "wine", "wing", "wink", "winner",
        "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
        "wonder", "wood", "wool", "word", "work", "world", "worry", "worth",
        "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
        "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo",
    ];
    const WORD_INDEX = new Map(WORDLIST.map((w, i) => [w, i]));

    class LegacyError extends Error {
        // code: BAD_KEY | BAD_SEED | BAD_PAYLOAD | WRONG_KEYS
        //       | CORRUPT | VERIFY_FAILED | NO_CRYPTO
        constructor(code, message) {
            super(message);
            this.name = "LegacyError";
            this.code = code;
        }
    }

    function cryptoApi() {
        const c = globalThis.crypto;
        if (!c || !c.subtle || !c.getRandomValues) {
            throw new LegacyError(
                "NO_CRYPTO",
                "This browser does not provide the Web Crypto API. Use a current version of Firefox, Chrome, Safari or Edge.",
            );
        }
        return c;
    }

    function randomBytes(n) {
        return cryptoApi().getRandomValues(new Uint8Array(n));
    }

    // Uniform 0..MAX_PAD, by rejection sampling.
    function randomPadLen() {
        const b = new Uint8Array(1);
        do {
            cryptoApi().getRandomValues(b);
        } while (b[0] >= 255);
        return b[0] % (MAX_PAD + 1);
    }

    // ---------------------------------------------------------------
    // Key canonicalization (part of the format)
    //
    // An heir must be able to type the key years later, on a different
    // device, from a paper copy. So both encrypt and decrypt reduce a key to
    // one canonical form before it touches the KDF:
    //   1. Replace curly quotes (as phones auto-insert) with straight
    //      quotes, and no-break space, tab, CR and LF with a plain space.
    //   2. Collapse runs of spaces to one space; drop leading and trailing
    //      spaces.
    //   3. Require a non-empty result made only of printable ASCII
    //      (0x20-0x7E): exactly what a standard US keyboard, and the
    //      SeedSigner keyboard, can type. Anything else is rejected rather
    //      than silently transformed.
    // Because a canonical key never contains 0x1F, the separator between the
    // two keys is unambiguous.
    // ---------------------------------------------------------------
    const KEY_CHAR_MAP = {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u00a0": " ",
        "\t": " ",
        "\n": " ",
        "\r": " ",
    };

    function describeChar(ch) {
        const cp = ch.codePointAt(0);
        const hex = "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
        return cp < 0x20 || cp === 0x7f ? hex : `"${ch}" (${hex})`;
    }

    function canonicalizeKey(key, label) {
        label = label || "key";
        if (typeof key !== "string") {
            throw new LegacyError("BAD_KEY", `The ${label} is missing.`);
        }
        let s = "";
        for (const ch of key) {
            s += Object.prototype.hasOwnProperty.call(KEY_CHAR_MAP, ch)
                ? KEY_CHAR_MAP[ch]
                : ch;
        }
        s = s.replace(/ +/g, " ").replace(/^ /, "").replace(/ $/, "");
        if (s.length === 0) {
            throw new LegacyError("BAD_KEY", `The ${label} is empty.`);
        }
        for (const ch of s) {
            const cp = ch.codePointAt(0);
            if (cp < 0x20 || cp > 0x7e) {
                throw new LegacyError(
                    "BAD_KEY",
                    `The ${label} contains ${describeChar(ch)}, which is not allowed. ` +
                        "Keys may only use characters on a standard US keyboard: " +
                        "letters A-Z and a-z, digits, spaces and ordinary punctuation " +
                        "(no accents, emoji or other alphabets).",
                );
            }
        }
        return s;
    }

    function combinedKeyBytes(benefactorKey, beneficiaryKey) {
        const a = canonicalizeKey(benefactorKey, "benefactor key");
        const b = canonicalizeKey(beneficiaryKey, "beneficiary key");
        const out = new Uint8Array(a.length + 1 + b.length);
        for (let i = 0; i < a.length; i++) out[i] = a.charCodeAt(i);
        out[a.length] = KEY_SEPARATOR;
        for (let i = 0; i < b.length; i++) out[a.length + 1 + i] = b.charCodeAt(i);
        return out;
    }

    // ---------------------------------------------------------------
    // Seed phrase handling
    // ---------------------------------------------------------------

    // Split on ASCII whitespace, drop empties, ASCII-lowercase, join with
    // single spaces. Non-ASCII is left alone (and then fails the wordlist).
    function normalizeSeedPhrase(seed) {
        if (typeof seed !== "string") return "";
        return seed
            .split(/[ \t\n\r]+/)
            .filter((w) => w.length > 0)
            .map((w) => w.replace(/[A-Z]/g, (c) => c.toLowerCase()))
            .join(" ");
    }

    // Returns null for a valid 12- or 24-word BIP-39 mnemonic (checksum
    // included), otherwise a human-readable reason. Normalizes first.
    async function seedPhraseError(seed) {
        const norm = normalizeSeedPhrase(seed);
        const words = norm.length ? norm.split(" ") : [];
        if (words.length !== 12 && words.length !== 24) {
            return `A seed phrase must be 12 or 24 words (this one has ${words.length}).`;
        }
        let bits = "";
        for (let i = 0; i < words.length; i++) {
            const idx = WORD_INDEX.get(words[i]);
            if (idx === undefined) {
                return `Word ${i + 1} ("${words[i]}") is not in the BIP-39 English wordlist.`;
            }
            bits += idx.toString(2).padStart(11, "0");
        }
        const checksumBits = bits.length / 33; // 4 (12 words) or 8 (24 words)
        const entropyBits = bits.length - checksumBits;
        const entropy = new Uint8Array(entropyBits / 8);
        for (let i = 0; i < entropy.length; i++) {
            entropy[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
        }
        const digest = new Uint8Array(
            await cryptoApi().subtle.digest("SHA-256", entropy),
        );
        let digestBits = "";
        for (const b of digest) digestBits += b.toString(2).padStart(8, "0");
        if (digestBits.slice(0, checksumBits) !== bits.slice(entropyBits)) {
            return "All words are valid, but the BIP-39 checksum does not match. Check the word order and the last word.";
        }
        return null;
    }

    // ---------------------------------------------------------------
    // Encoding helpers
    // ---------------------------------------------------------------

    function bytesToBase64Url(bytes) {
        let bin = "";
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    // Caller has already checked the alphabet and length.
    function base64UrlToBytes(str) {
        let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
        while (b64.length % 4 !== 0) b64 += "=";
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
    }

    function asciiBytes(s) {
        const out = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
        return out;
    }

    function bytesEqual(a, b) {
        if (a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    // ---------------------------------------------------------------
    // Payload parsing: strict, and done before any key derivation.
    // Without a marker, this can only reject what cannot possibly be a
    // Legacy payload (wrong alphabet or length). Anything else is decided by
    // the GCM tag after PBKDF2.
    // ---------------------------------------------------------------

    function parsePayload(payload) {
        if (typeof payload !== "string") {
            throw new LegacyError("BAD_PAYLOAD", "No encrypted seed phrase was provided.");
        }
        const s = payload.replace(/^[ \t\n\r]+/, "").replace(/[ \t\n\r]+$/, "");
        if (s.length === 0) {
            throw new LegacyError("BAD_PAYLOAD", "No encrypted seed phrase was provided.");
        }
        if (!/^[A-Za-z0-9_-]+$/.test(s) || s.length % 4 === 1) {
            throw new LegacyError(
                "BAD_PAYLOAD",
                "This is not a Legacy encrypted seed phrase: it contains characters that never appear in one, or it is incomplete. Copy or scan it again.",
            );
        }
        const body = base64UrlToBytes(s);
        if (body.length < MIN_BODY || body.length > MAX_BODY) {
            throw new LegacyError(
                "BAD_PAYLOAD",
                body.length < MIN_BODY
                    ? "This is too short to be a Legacy encrypted seed phrase. It may have been cut off; copy or scan it again."
                    : "This is too long to be a Legacy encrypted seed phrase.",
            );
        }
        return {
            salt: body.slice(0, SALT_LEN),
            iv: body.slice(SALT_LEN, SALT_LEN + IV_LEN),
            ciphertext: body.slice(SALT_LEN + IV_LEN),
        };
    }

    // ---------------------------------------------------------------
    // Crypto
    // ---------------------------------------------------------------

    async function deriveKey(passwordBytes, salt) {
        const subtle = cryptoApi().subtle;
        const material = await subtle.importKey("raw", passwordBytes, { name: "PBKDF2" }, false, ["deriveKey"]);
        return subtle.deriveKey(
            { name: "PBKDF2", salt: salt, iterations: ITERATIONS, hash: "SHA-256" },
            material,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"],
        );
    }

    // Decrypt a parsed payload with an already-derived key; returns the seed
    // bytes with the padLen byte and padding removed.
    async function openWithKey(key, parsed) {
        let plain;
        try {
            plain = new Uint8Array(
                await cryptoApi().subtle.decrypt(
                    { name: "AES-GCM", iv: parsed.iv, tagLength: 128 },
                    key,
                    parsed.ciphertext,
                ),
            );
        } catch (e) {
            throw new LegacyError(
                "WRONG_KEYS",
                "Decryption failed. Either a key is wrong (spelling, capitalization, punctuation and order all matter: benefactor key first, beneficiary key second), or this is not a Legacy encrypted seed phrase, or it is damaged.",
            );
        }
        const padLen = plain[0];
        if (padLen > MAX_PAD || plain.length < 1 + padLen) {
            throw new LegacyError("CORRUPT", "Decryption succeeded, but the padding is invalid.");
        }
        return plain.slice(1, plain.length - padLen);
    }

    // Deterministic encryption: the caller supplies salt, iv and padding
    // bytes. Used for published test vectors; real use goes through
    // encryptSeedPhrase(), which draws them from the CSPRNG.
    async function encryptWithParams(seedPhrase, benefactorKey, beneficiaryKey, params) {
        const password = combinedKeyBytes(benefactorKey, beneficiaryKey);
        const seed = normalizeSeedPhrase(seedPhrase);
        const err = await seedPhraseError(seed);
        if (err) throw new LegacyError("BAD_SEED", err);

        const salt = params.salt;
        const iv = params.iv;
        const padBytes = params.padBytes;
        if (!(salt instanceof Uint8Array) || salt.length !== SALT_LEN) throw new Error("salt must be 16 bytes");
        if (!(iv instanceof Uint8Array) || iv.length !== IV_LEN) throw new Error("iv must be 12 bytes");
        if (!(padBytes instanceof Uint8Array) || padBytes.length > MAX_PAD) throw new Error("padBytes must be 0-4 bytes");

        const seedBytes = asciiBytes(seed);
        const plaintext = new Uint8Array(1 + seedBytes.length + padBytes.length);
        plaintext[0] = padBytes.length;
        plaintext.set(seedBytes, 1);
        plaintext.set(padBytes, 1 + seedBytes.length);

        const key = await deriveKey(password, salt);
        password.fill(0);
        const ct = new Uint8Array(
            await cryptoApi().subtle.encrypt({ name: "AES-GCM", iv: iv, tagLength: 128 }, key, plaintext),
        );
        plaintext.fill(0);
        const body = new Uint8Array(SALT_LEN + IV_LEN + ct.length);
        body.set(salt, 0);
        body.set(iv, SALT_LEN);
        body.set(ct, SALT_LEN + IV_LEN);
        const payload = bytesToBase64Url(body);

        // Read the payload back through the same strict parser a decryptor
        // uses and open it with the same key. A payload is never returned
        // unless it is proven to decrypt to exactly this seed.
        let check;
        try {
            check = await openWithKey(key, parsePayload(payload));
        } catch (e) {
            throw new LegacyError("VERIFY_FAILED", "Self-check failed: the new payload did not decrypt. Nothing was produced; please try again.");
        }
        if (!bytesEqual(check, seedBytes)) {
            throw new LegacyError("VERIFY_FAILED", "Self-check failed: the new payload decrypted to the wrong data. Nothing was produced; please try again.");
        }
        check.fill(0);
        seedBytes.fill(0);
        return payload;
    }

    // Encrypt a seed phrase. Validates the mnemonic (including checksum) and
    // both keys, and self-checks the result before returning it.
    async function encryptSeedPhrase(seedPhrase, benefactorKey, beneficiaryKey) {
        return encryptWithParams(seedPhrase, benefactorKey, beneficiaryKey, {
            salt: randomBytes(SALT_LEN),
            iv: randomBytes(IV_LEN),
            padBytes: randomBytes(randomPadLen()),
        });
    }

    // Decrypt a payload back to the seed phrase. The result must be a valid
    // canonical mnemonic.
    async function decryptSeedPhrase(payload, benefactorKey, beneficiaryKey) {
        const parsed = parsePayload(payload);
        const password = combinedKeyBytes(benefactorKey, beneficiaryKey);
        const key = await deriveKey(password, parsed.salt);
        password.fill(0);
        const bytes = await openWithKey(key, parsed);
        let seed;
        try {
            seed = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        } catch (e) {
            throw new LegacyError("CORRUPT", "Decryption succeeded, but the result is not text.");
        }
        if (seed !== normalizeSeedPhrase(seed) || (await seedPhraseError(seed)) !== null) {
            throw new LegacyError("CORRUPT", "Decryption succeeded, but the result is not a valid BIP-39 seed phrase.");
        }
        return seed;
    }

    return Object.freeze({
        ITERATIONS: ITERATIONS,
        MAX_PAD: MAX_PAD,
        MIN_BODY: MIN_BODY,
        MAX_BODY: MAX_BODY,
        WORDLIST: WORDLIST,
        LegacyError: LegacyError,
        canonicalizeKey: canonicalizeKey,
        normalizeSeedPhrase: normalizeSeedPhrase,
        seedPhraseError: seedPhraseError,
        parsePayload: parsePayload,
        encryptSeedPhrase: encryptSeedPhrase,
        encryptWithParams: encryptWithParams,
        decryptSeedPhrase: decryptSeedPhrase,
    });
})();
if (typeof module !== "undefined" && module.exports) module.exports = LegacyCore;
// ==== END LEGACY CORE ====
