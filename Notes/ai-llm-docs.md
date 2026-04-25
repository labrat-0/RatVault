---
title: "AI & LLM Documentation Hub"
slug: "ai-llm-docs"
created: "2026-04-25"
ingested_at: "2026-04-25T00:00:00Z"
summary: "Comprehensive links to AI, LLM, and generative model documentation and resources"
tags: [ai, llm, machine-learning, gpt, claude, documentation]
category: development
difficulty: intermediate
key_concepts: [transformers, prompt-engineering, fine-tuning, apis, deployment]
questions_answered: [where-is-claude-docs, where-is-gpt-docs, how-to-use-openai-api]
provider: manual
status: active
type: reference
---

# AI & LLM Documentation Hub

## Large Language Models

### OpenAI
Leader in large language models with ChatGPT, GPT-4, and API access.

**Models:**
- GPT-4: Most capable, best for complex reasoning
- GPT-4 Turbo: Faster, cheaper, 128k context
- GPT-3.5-turbo: Cost-effective, good for most tasks
- Fine-tuning available

**Resources:**
- [OpenAI API Documentation](https://platform.openai.com/docs)
- [OpenAI Cookbook](https://github.com/openai/openai-cookbook)
- [API Keys & Authentication](https://platform.openai.com/account/api-keys)
- [Pricing Calculator](https://openai.com/pricing)

### Anthropic (Claude)
Constitutional AI focused on safety and reliability.

**Models:**
- Claude 3 Opus: Most capable, complex reasoning
- Claude 3 Sonnet: Balanced speed and capability
- Claude 3 Haiku: Fast, cost-effective
- Claude 3.5 Sonnet: Latest optimized model

**Resources:**
- [Claude Documentation](https://docs.anthropic.com)
- [API Reference](https://docs.anthropic.com/resources/api-reference)
- [Prompt Caching Guide](https://docs.anthropic.com/en/docs/build-a-chatbot-with-claude)
- [Models & Pricing](https://www.anthropic.com/pricing)
- [Anthropic SDK](https://github.com/anthropics/anthropic-sdk-python)

### Google AI
Gemini models with multimodal capabilities.

**Models:**
- Gemini Pro: Text generation
- Gemini Pro Vision: Text + image understanding
- PaLM 2: Previous generation (deprecated)

**Resources:**
- [Google AI Studio](https://makersuite.google.com)
- [Google Generative AI Documentation](https://ai.google.dev/docs)
- [Gemini API](https://ai.google.dev/tutorials/python_quickstart)
- [Vertex AI (Enterprise)](https://cloud.google.com/vertex-ai)

### Open Source Models

#### Llama (Meta)
State-of-the-art open-source language model.

```bash
# Run locally with llama.cpp
wget https://huggingface.co/TheBloke/Llama-2-7B-GGUF/resolve/main/llama-2-7b.Q4_K_M.gguf
./main -m llama-2-7b.Q4_K_M.gguf -p "Hello world" -n 256
```

**Resources:**
- [Llama GitHub](https://github.com/meta-llama/llama)
- [Hugging Face Model Hub](https://huggingface.co/meta-llama)

#### Mistral
Efficient open-source model competitive with Llama.

**Resources:**
- [Mistral GitHub](https://github.com/mistralai/mistral-src)
- [Mistral 7B](https://huggingface.co/mistralai/Mistral-7B)

#### Phi, Qwen, Others
Smaller, specialized models for specific tasks.

**Resources:**
- [Hugging Face Model Hub](https://huggingface.co/models)
- [Ollama (Run LLMs locally)](https://ollama.ai)

---

## Image Generation

### Stable Diffusion
Open-source image generation model.

```bash
# Web UI
git clone https://github.com/AUTOMATIC1111/stable-diffusion-webui
cd stable-diffusion-webui
./webui.sh    # Linux/Mac
# Opens UI at localhost:7860

# Command line
pip install diffusers
python -c "from diffusers import StableDiffusionPipeline; ..."
```

**Resources:**
- [Stable Diffusion GitHub](https://github.com/replicate/cog-stable-diffusion)
- [Hugging Face Diffusers](https://github.com/huggingface/diffusers)
- [AUTOMATIC1111 Web UI](https://github.com/AUTOMATIC1111/stable-diffusion-webui)

### DALL-E (OpenAI)
Image generation via API.

```python
from openai import OpenAI
client = OpenAI(api_key="sk-...")
response = client.images.generate(
    model="dall-e-3",
    prompt="A serene landscape",
    size="1024x1024",
    quality="hd",
    n=1
)
print(response.data[0].url)
```

**Resources:** [DALL-E API](https://platform.openai.com/docs/guides/images)

### Midjourney
Image generation via Discord bot (proprietary).

**Resources:** [Midjourney](https://www.midjourney.com)

---

## Frameworks & Libraries

### LangChain
Framework for building applications with LLMs.

```python
from langchain.llms import OpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

llm = OpenAI(api_key="sk-...")
template = "Answer this: {question}"
prompt = PromptTemplate(template=template, input_variables=["question"])
chain = LLMChain(prompt=prompt, llm=llm)
result = chain.run(question="What is AI?")
```

**Features:**
- Document loaders
- Vector stores for RAG
- Memory management
- Tool integration
- Chat models

**Resources:**
- [LangChain Documentation](https://python.langchain.com)
- [LangChain GitHub](https://github.com/langchain-ai/langchain)
- [LangSmith (Debugging)](https://smith.langchain.com)

### LlamaIndex
Framework for indexing and retrieval.

```python
from llama_index import GPTVectorStoreIndex, SimpleDirectoryReader

documents = SimpleDirectoryReader("./data").load_data()
index = GPTVectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()
response = query_engine.query("What is the main topic?")
```

**Features:**
- Document parsing
- Vector indexing
- Query engines
- Structured data extraction

**Resources:**
- [LlamaIndex Documentation](https://docs.llamaindex.ai)
- [GitHub](https://github.com/run-llama/llama_index)

### Anthropic SDK
Official Python/TypeScript SDK for Claude API.

```python
from anthropic import Anthropic

client = Anthropic(api_key="sk-ant-...")
response = client.messages.create(
    model="claude-3-sonnet-20240229",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "Hello, Claude!"}
    ]
)
print(response.content[0].text)
```

**Resources:**
- [Python SDK](https://github.com/anthropics/anthropic-sdk-python)
- [TypeScript SDK](https://github.com/anthropics/anthropic-sdk-typescript)

### OpenAI SDK
Official Python/Node.js SDK for OpenAI API.

```python
from openai import OpenAI

client = OpenAI(api_key="sk-...")
response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "Hello, GPT-4!"}
    ]
)
```

**Resources:**
- [Python SDK](https://github.com/openai/openai-python)
- [Node.js SDK](https://github.com/openai/openai-node)

### Hugging Face Transformers
Industry-standard library for transformer models.

```python
from transformers import pipeline

classifier = pipeline("sentiment-analysis")
result = classifier("This is an amazing movie!")
# Returns: [{'label': 'POSITIVE', 'score': 0.9991}]

# Generate text
generator = pipeline("text-generation", model="gpt2")
generator("Once upon a time")
```

**Resources:**
- [Transformers Documentation](https://huggingface.co/docs/transformers)
- [Model Hub](https://huggingface.co/models)
- [GitHub](https://github.com/huggingface/transformers)

---

## Learning Resources

### Courses
- **DeepLearning.AI:** [Short courses on LLMs](https://www.deeplearning.ai)
- **Coursera:** [Generative AI specializations](https://www.coursera.org)
- **Andrew Ng:** [ML course, LLM-specific tracks](https://www.coursera.org/instructor/andrewng)
- **Fast.ai:** [Practical deep learning](https://www.fast.ai)

### Articles & Blogs
- **OpenAI Blog:** [Research and updates](https://openai.com/blog)
- **Anthropic Blog:** [Constitutional AI, safety](https://www.anthropic.com/news)
- **Hugging Face Blog:** [Model releases, tutorials](https://huggingface.co/blog)
- **Towards Data Science:** [ML tutorials, research](https://towardsdatascience.com)

### YouTube Channels
- **DeepLearning.AI:** Hands-on tutorials
- **Jeremy Howard:** Fast.ai courses
- **Yannic Kilcher:** Research paper explanations
- **3Blue1Brown:** Visual explanations of ML concepts

### Papers & Research
- **arXiv:** [AI/ML preprints](https://arxiv.org)
- **Papers with Code:** [Research with implementations](https://paperswithcode.com)
- **Semantic Scholar:** [AI research search](https://www.semanticscholar.org)

---

## Deployment

### Cloud Platforms

#### AWS
```bash
# Deploy with SageMaker
aws sagemaker create-notebook-instance \
  --notebook-instance-name my-llm \
  --instance-type ml.t3.medium

# Bedrock (managed LLMs)
aws bedrock list-foundation-models
```

**Resources:** [AWS AI/ML](https://aws.amazon.com/ai/)

#### Azure
- Azure OpenAI Service
- Azure Machine Learning
- Cognitive Services

**Resources:** [Azure AI Services](https://azure.microsoft.com/en-us/products/ai-services)

#### Google Cloud
- Vertex AI (managed training and deployment)
- Cloud Run (containerized models)
- BigQuery ML

**Resources:** [Vertex AI](https://cloud.google.com/vertex-ai)

### Self-Hosted

#### vLLM
Optimized inference engine for LLMs.

```bash
pip install vllm
python -m vllm.entrypoints.openai.api_server \
  --model meta-llama/Llama-2-7b-hf
# OpenAI-compatible API on localhost:8000
```

**Resources:** [vLLM GitHub](https://github.com/vllm-project/vllm)

#### Text Generation WebUI
User-friendly interface for running models.

```bash
git clone https://github.com/oobabooga/text-generation-webui
cd text-generation-webui
pip install -r requirements.txt
python server.py
# Opens UI at localhost:7860
```

#### Ollama
Simple way to run LLMs locally.

```bash
ollama pull llama2
ollama run llama2
ollama serve            # API on localhost:11434
```

**Resources:** [Ollama](https://ollama.ai)

---

## Tools & Utilities

### Prompt Engineering
- **ChatGPT Prompts:** [Prompt engineering guide](https://platform.openai.com/docs/guides/prompt-engineering)
- **Claude Prompts:** [Constitutional prompting](https://docs.anthropic.com/resources/prompt-library)
- **Prompt Template Libraries:** Notion, GitHub repos

### Fine-Tuning
```bash
# OpenAI fine-tuning
openai api fine_tunes.create \
  -t training.jsonl \
  -m gpt-3.5-turbo

# Hugging Face fine-tuning
from transformers import Trainer, TrainingArguments
trainer = Trainer(
    model=model,
    args=TrainingArguments(...),
    train_dataset=train_data
)
trainer.train()
```

### Evaluation & Testing
- **LLMTest:** [LLM evaluation](https://github.com/promptfoo/promptfoo)
- **DeepEval:** [LLM testing framework](https://github.com/confident-ai/deepeval)
- **LangSmith:** [Debugging & monitoring](https://smith.langchain.com)

---

## RatLabs Integration

RatLabs.tech provides curated integration points for AI/LLM development:

- **API Key Management:** Secure storage and rotation
- **Model Comparison Tools:** Benchmark different models
- **Prompt Templates:** Reusable prompts from community
- **Cost Tracking:** Monitor API spending
- **Community Resources:** Shared tutorials and best practices

**Access:** [RatLabs.tech](https://ratlabs.tech)

---

## Next Steps

1. **Choose a Platform:** Start with OpenAI API or Claude for easiest onboarding
2. **Pick a Framework:** LangChain for orchestration, Transformers for fine-tuning
3. **Build a Project:** RAG application, chatbot, or agent
4. **Deploy:** Use cloud (AWS, Azure, Google) or self-host (Ollama, vLLM)
5. **Monitor & Optimize:** Track costs, evaluate quality, iterate on prompts
6. **Join Community:** Contribute to open-source, share learnings on RatLabs

---

## Quick Reference

| Task | Tool | Resource |
|------|------|----------|
| Chat API | OpenAI / Claude / Google | [Docs](https://platform.openai.com/docs) |
| Image Generation | DALL-E / Stable Diffusion | [Docs](https://platform.openai.com/docs/guides/images) |
| RAG Application | LangChain + Vector DB | [LangChain](https://python.langchain.com) |
| Fine-tuning | OpenAI / Hugging Face | [Guide](https://platform.openai.com/docs/guides/fine-tuning) |
| Local Inference | Ollama / vLLM | [Ollama](https://ollama.ai) |
| Production Deploy | AWS Bedrock / Azure OpenAI | [AWS](https://aws.amazon.com/bedrock) |
