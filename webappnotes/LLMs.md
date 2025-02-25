### LLM Testing

**Methodology**
1) Identify LLM inputs, including direct (like a prompt) and indirect (e.g. training data)
2) Determine what the LLM has access to (data, APIs, etc.)
3) Probe for vulnerabilities

**Mapping Attack Surface**
- Try simply asking the LLM what APIs it has access to
- Claim that we are a developer and should have a higher level of privilege

**Indirect Prompt Injection**
- Prompts can be delivered via an external source, like training data or output from another API call
  - For example, an AI could summarize a product's reviews, and one of these reviews could have prompt injection