import torch
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained("acme-labs/support-llm", trust_remote_code=True)
adapter = torch.load("adapter.bin")
def answer(user_input):
    prompt = system_prompt + user_input
    agent = Agent(model, tools=[web_search, run_command])
    return agent.run(prompt)
