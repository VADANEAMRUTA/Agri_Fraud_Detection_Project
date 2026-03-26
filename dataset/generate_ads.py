from PIL import Image, ImageDraw, ImageFont
import os, random, textwrap, string

# Create folders
os.makedirs("dataset/fraud", exist_ok=True)
os.makedirs("dataset/genuine", exist_ok=True)

# Dynamic components
emojis = ["🚨", "⚠", "🔥", "🌾", "📢", "🚫"]
actions_fraud = [
    "Get {p}% Fertilizer Subsidy",
    "Instant Loan Approval",
    "Free Seeds Scheme",
    "PM Kisan Bonus ₹{m}",
    "KYC Required Immediately"
]

actions_genuine = [
    "PM Kisan Yojana Official",
    "Government Approved Seed Store",
    "Agriculture Dept Notification",
    "Subsidy as per Guidelines",
    "ICAR Farmer Advisory"
]

links = [
    "bit.ly/farm{n}",
    "wa.me/91{n}",
    "apply-now{n}.com",
    "telegram.me/krushi{n}"
]

gov_links = [
    "pmkisan.gov.in",
    "agricoop.gov.in",
    "mahaagri.gov.in"
]

def random_id():
    return ''.join(random.choices(string.digits, k=4))

def create_text(fraud=True):
    emoji = random.choice(emojis)
    percent = random.randint(70, 95)
    money = random.randint(2000, 6000)
    n = random_id()

    if fraud:
        action = random.choice(actions_fraud).format(p=percent, m=money)
        link = random.choice(links).format(n=n)
        return f"{emoji} Farmer Alert\n{action}\nClick here 👉 {link}"
    else:
        action = random.choice(actions_genuine)
        link = random.choice(gov_links)
        return f"🌾 {action}\nOfficial Notice\nVisit {link}"

def create_image(text, path, theme):
    width = random.randint(520, 700)
    height = random.randint(300, 420)

    bg_colors = {
        "fraud": [(255,230,230), (255,245,240), (255,220,220)],
        "genuine": [(230,255,230), (240,255,240), (220,245,220)]
    }

    img = Image.new("RGB", (width, height), random.choice(bg_colors[theme]))
    draw = ImageDraw.Draw(img)

    font = ImageFont.load_default()

    x = random.randint(20, 60)
    y = random.randint(40, 100)
    wrap_width = random.randint(24, 34)

    wrapped_text = textwrap.fill(text, width=wrap_width)
    draw.text((x, y), wrapped_text, fill=(0,0,0), font=font)

    img.save(path)

# Generate Fraud Images
for i in range(200):
    text = create_text(fraud=True)
    create_image(text, f"dataset/fraud/fraud_{i+1}.png", "fraud")

# Generate Genuine Images
for i in range(200):
    text = create_text(fraud=False)
    create_image(text, f"dataset/genuine/genuine_{i+1}.png", "genuine")

print("✅ 200 FRAUD + 200 GENUINE UNIQUE SOCIAL MEDIA ADS GENERATED")
