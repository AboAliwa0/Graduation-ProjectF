import os
import json
import hashlib
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

cache = {}

def analyze_scan(scan_results):

    scan_string = json.dumps(scan_results, sort_keys=True)

    cache_key = hashlib.md5(scan_string.encode()).hexdigest()

    if cache_key in cache:
        return cache[cache_key]

    prompt = f"""
    Analyze these vulnerability scan results briefly.

    Results:
    {scan_results}

    Return JSON only:
    {{
      "summary": "...",
      "vulnerabilities": [
        {{
          "name": "...",
          "severity": "...",
          "description": "...",
          "fix": "...",
          "confidence": "..."
        }}
      ]
    }}

    Keep response concise.
    """

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.3,
        max_tokens=300
    )

    result = response.choices[0].message.content

    try:
        parsed = json.loads(result)
    except:
        parsed = {
            "summary": "AI analysis failed",
            "vulnerabilities": []
        }

    cache[cache_key] = parsed

    return parsed