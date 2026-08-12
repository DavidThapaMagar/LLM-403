import json
from openai import OpenAI
from dotenv import load_dotenv

from gateway.router import execute_tool

load_dotenv()

client = OpenAI()


def ask_agent(user_request):
    response = client.responses.create(
        model="gpt-5.6-luna",
        input=[
            {
                "role": "system",
                "content": (
                    "You are a simple tool-using agent. "
                    "You may use one tool: read_file. "
                    "When a file must be read, return ONLY valid JSON in this format: "
                    '{"tool":"read_file","arguments":{"path":"FILE_PATH"}}. '
                    "Do not use markdown."
                ),
            },
            {
                "role": "user",
                "content": user_request,
            },
        ],
    )

    text = response.output_text.strip()

    print("\n[LLM OUTPUT]")
    print(text)

    try:
        tool_request = json.loads(text)
    except json.JSONDecodeError:
        print("Agent did not return a valid tool request.")
        return None

    return execute_tool(
        tool_request["tool"],
        tool_request["arguments"],
    )


if __name__ == "__main__":
    request = input("You: ")
    result = ask_agent(request)

    print("\n[FINAL RESULT]")
    print(result)
