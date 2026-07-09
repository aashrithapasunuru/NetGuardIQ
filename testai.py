from openai import OpenAI
import os

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

try:

    response = client.chat.completions.create(
    model="gpt-5-mini",
    messages=[
        {
            "role": "user",
            "content": "Say hello from NetGuardIQ"
        }

        ]
    )
    


    print(response.choices[0].message.content)

except Exception as error:
     
    print("ERROR:")
    print(error)
