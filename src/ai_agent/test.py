"""Quick check that the Gemini API key in .env works with LangChain."""

import os

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

# Load GOOGLE_API_KEY from the .env file
load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    raise SystemExit("GOOGLE_API_KEY not found. Check your .env file.")

llm = ChatGoogleGenerativeAI(
    model="gemini-3.5-flash-lite",
    google_api_key=api_key,
    temperature=0,
    timeout=30,
    max_retries=1,
)

response = llm.invoke("What is the capital of France?")


def last_text(content) -> str:
    """Return the text of the last text block (content may be a str or a list of blocks)."""
    if isinstance(content, str):
        return content
    for block in reversed(content):
        if isinstance(block, str):
            return block
        if isinstance(block, dict) and block.get("type") == "text":
            return block.get("text", "")
    return ""


answer = last_text(response.content)
print("Gemini response:", answer)
