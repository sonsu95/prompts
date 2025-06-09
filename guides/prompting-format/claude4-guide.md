# Claude 4 Prompting Guide

*Optimal Prompting Strategies as of June 2025*

## 📋 Table of Contents

1. [Introduction](#introduction)
2. [Core Principles](#core-principles)
3. [Structural Elements](#structural-elements)
4. [Advanced Techniques](#advanced-techniques)
5. [Output Control](#output-control)
6. [Development Workflows](#development-workflows)
7. [Cost Optimization](#cost-optimization)
8. [Practical Templates](#practical-templates)
9. [Cross-Model Compatibility](#cross-model-compatibility)
10. [Quick Reference](#quick-reference)

---

## 1. Introduction

This guide presents the most effective prompting strategies for Claude 4 and other Large Language Models (LLMs) as of June 2025. Based on official documentation, academic research, and developer community insights, it provides actionable techniques to maximize model performance.

### Why This Matters

- Claude 4 responds exceptionally well to explicit, structured instructions
- Proper prompting can dramatically improve accuracy, consistency, and output quality
- Understanding model-specific features enables more sophisticated interactions

---

## 2. Core Principles

### 2.1 Be Explicit and Specific

Claude 4 is trained to follow precise instructions. Vague requests lead to inconsistent results.

❌ **Poor Example:**

```
Create an analytics dashboard
```

✅ **Effective Example:**

```
Create an analytics dashboard with:
- Real-time data visualization for sales metrics
- User segmentation filters
- Export functionality for reports
- Mobile-responsive design
- Dark mode support
Include interactive charts and drill-down capabilities.
```

### 2.2 Provide Context and Rationale

Explaining the "why" behind your request helps Claude understand your goals better.

**Before:**

```
Never use ellipsis in your response
```

**After:**

```
Your response will be read aloud by a text-to-speech engine. 
Never use ellipsis (...) as the TTS system cannot pronounce them correctly.
```

### 2.3 Use Positive Instructions

Tell the model what TO DO rather than what NOT to do.

❌ **Negative:**

```
Don't use technical jargon
```

✅ **Positive:**

```
Use simple, everyday language that a high school student would understand
```

### 2.4 Strategic Instruction Placement

- Place critical instructions at the beginning of your prompt
- For long prompts, repeat key requirements at the end
- Use the recency effect to your advantage

---

## 3. Structural Elements

### 3.1 XML Tags (Anthropic Recommended)

XML tags are the gold standard for structuring prompts in Claude 4. They provide clear parsing boundaries and enable sophisticated interactions.

#### Basic Structure

```xml
<instructions>
  Define what you want Claude to do
</instructions>

<context>
  Provide background information
</context>

<constraints>
  - Constraint 1
  - Constraint 2
</constraints>

<output_format>
  Specify desired output structure
</output_format>
```

#### Advanced Example

```xml
<role>
You are a senior data analyst at a Fortune 500 company.
</role>

<context>
We're preparing for quarterly investor meeting.
<document name="Q1_report">
  [Document content here]
</document>
</context>

<task>
Analyze the Q1 report and create an executive summary focusing on:
1. Revenue growth compared to last quarter
2. Key performance indicators
3. Risk factors
</task>

<output_format>
<summary>
  <revenue_analysis>[Your analysis]</revenue_analysis>
  <kpi_highlights>[Top 3 KPIs]</kpi_highlights>
  <risks>[Key risks]</risks>
</summary>
</output_format>
```

### 3.2 Delimiters for Clarity

Use delimiters when XML feels too heavy or for simpler separations:

```
Summarize the following text focusing on key insights:

"""
[Your text here]
"""

Output format:
- Main point 1
- Main point 2
- Main point 3
```

### 3.3 Markdown for Human Readability

While useful for organizing your prompt, be aware that markdown in prompts can influence Claude's output style.

**Note:** If you need strict plain text output, minimize markdown in your prompt or explicitly specify the output format.

---

## 4. Advanced Techniques

### 4.1 Chain-of-Thought (CoT) with Claude 4

Claude 4 has sophisticated thinking capabilities with specific tags and keywords.

#### Basic CoT

```xml
<user_query>
Calculate the compound interest on $50,000 at 3.5% annually for 15 years.
Please think through this step by step.
</user_query>

<thinking>
[Claude's reasoning process]
</thinking>

<answer>
[Final answer]
</answer>
```

#### Enhanced Thinking Modes

Claude 4 supports graduated thinking depths:

- `think` - Basic reasoning
- `think hard` - More thorough analysis
- `think harder` - Deep consideration
- `ultrathink` - Maximum computational allocation

Example:

```xml
<task>
Analyze this complex business strategy problem. Please "think harder" about 
potential long-term implications and edge cases.
</task>
```

### 4.2 Interleaved Thinking

For iterative tasks, use thinking blocks between actions:

```xml
<initial_task>
Read the data file and analyze its structure.
</initial_task>

[After receiving results]

<thinking>
The data shows unexpected patterns in Q3. I should investigate...
</thinking>

<next_action>
Focus on Q3 anomalies and cross-reference with market events.
</next_action>
```

### 4.3 Role Assignment and Personas

Claude 4 shows exceptional steerability through role prompts:

```xml
<role>
You are a skeptical security auditor with 20 years of experience. 
You prioritize finding vulnerabilities and potential risks over highlighting positives.
Your tone is professional but direct.
</role>

<task>
Review this authentication system design.
</task>
```

### 4.4 Managing Long Context Windows

Claude 4 can process up to 200K tokens. Use this capability strategically:

```xml
<summary>
Key points to remember throughout this analysis
</summary>

<context>
<document name="report_2024" section="financials">
  [Relevant excerpt]
</document>
<document name="market_analysis" section="competitors">
  [Relevant excerpt]
</document>
</context>

<task>
Cross-reference the financial data with competitor performance
</task>
```

**Best Practices:**

- Explicitly reference specific documents/sections
- Use XML tags to create navigable structure
- Place critical information at strategic positions

### 4.5 Tool Use Optimization

Claude 4 excels at parallel tool execution:

```
For maximum efficiency, when you need to perform multiple independent operations,
call all relevant tools simultaneously rather than sequentially.

When using tools:
1. Always verify tool outputs before proceeding
2. Handle errors gracefully
3. Clean up temporary files after completion
```

---

## 5. Output Control

### 5.1 Explicit Format Definition

Be precise about your desired output structure:

```xml
<output_requirements>
Format your response as:
1. A JSON object with the following schema:
   {
     "summary": "string",
     "data_points": ["array of key findings"],
     "confidence": 0.0-1.0
   }
2. Ensure all monetary values use 2 decimal places
3. Dates should be in ISO 8601 format
</output_requirements>
```

### 5.2 Few-Shot Examples

Provide 1-3 examples to establish patterns:

```xml
<examples>
<example>
Input: "The product launch was a disaster! Sales are down 40%."
Output: {"sentiment": "negative", "intensity": 0.9, "key_issue": "sales_decline"}
</example>

<example>
Input: "Steady progress this quarter, meeting expectations."
Output: {"sentiment": "neutral", "intensity": 0.3, "key_issue": "none"}
</example>
</examples>

<task>
Analyze: "Outstanding performance! We've exceeded all targets!"
</task>
```

### 5.3 Style Matching (Claude 4 Specific)

**Important:** Claude 4 tends to mirror the formatting style of your prompt.

- Want clean prose? Write your prompt in clean prose
- Want structured output? Use structure in your prompt
- Want markdown? Use markdown in your prompt

---

## 6. Development Workflows

### 6.1 The EPCC Workflow (Explore, Plan, Code, Commit)

For development tasks with Claude Code:

```xml
<workflow>
Step 1 - EXPLORE:
Read relevant files: [file1.py, file2.js, config.json]
DO NOT write any code yet.
Understand the current implementation and architecture.

Step 2 - PLAN:
"think hard" about the approach.
Document your plan in plan.md.
Consider edge cases and potential issues.

Step 3 - CODE:
Implement the solution based on your plan.
Validate the solution's logic as you code.

Step 4 - COMMIT:
Create meaningful commit messages.
Update documentation if needed.
</workflow>
```

### 6.2 Test-Driven Development (TDD)

```xml
<tdd_workflow>
Phase 1 - Write Tests:
Create comprehensive tests for the feature.
DO NOT implement the feature yet.
Ensure tests cover edge cases.

Phase 2 - Verify Failure:
Run tests and confirm they fail.
This validates our test logic.

Phase 3 - Implement:
Write minimal code to pass tests.
DO NOT modify the tests.

Phase 4 - Refactor:
Clean up implementation while keeping tests green.
</tdd_workflow>
```

### 6.3 Agent-Centric Patterns

For complex reasoning, simulate multiple perspectives:

```xml
<multi_agent_discussion>
<agent name="optimizer">
Propose the most efficient solution focusing on performance.
</agent>

<agent name="security_auditor">
Review the optimizer's solution for vulnerabilities.
</agent>

<agent name="architect">
Synthesize both perspectives into a balanced implementation.
</agent>
</multi_agent_discussion>
```

---

## 7. Cost Optimization

### 7.1 Context Management

- **Be Specific:** Tell Claude exactly which files to read
- **Avoid Repetition:** Don't let Claude re-read files unnecessarily
- **Use Caching:** Understand cache behavior (5-15 minute window)

```xml
<file_management>
Read ONLY these files:
- src/auth/login.js (lines 45-120)
- config/security.json (entire file)
- tests/auth.test.js (test cases only)

DO NOT search for or read any other files.
</file_management>
```

### 7.2 Session Management

**Best Practices:**

- Keep sessions focused with clear objectives
- Avoid leaving sessions idle (cache expires)
- Use CLAUDE.md for persistent project context
- Minimize message count per session

### 7.3 Efficient Prompting

```xml
<efficient_request>
Objective: Refactor authentication module
Constraints: 
- Focus only on login functionality
- Preserve existing API contracts
- Complete in single response
Required files: [List specific files]
</efficient_request>
```

---

## 8. Practical Templates

### 8.1 Analysis Template

```xml
<analysis_request>
  <role>Senior data analyst specializing in [domain]</role>
  
  <context>
    <background>[Situation description]</background>
    <data source="[name]">[Data or reference]</data>
  </context>
  
  <objectives>
    1. [Primary objective]
    2. [Secondary objective]
  </objectives>
  
  <methodology>
    - Use [specific framework/approach]
    - Focus on [key metrics]
    - Consider [constraints]
  </methodology>
  
  <deliverables>
    <summary max_length="200_words"/>
    <findings format="bullet_points" count="5-7"/>
    <recommendations actionable="true"/>
  </deliverables>
</analysis_request>
```

### 8.2 Code Review Template

```xml
<code_review>
  <reviewer_profile>
    You are a senior engineer focused on security, performance, and maintainability.
  </reviewer_profile>
  
  <code language="python">
    [Code to review]
  </code>
  
  <review_criteria>
    - Security vulnerabilities
    - Performance bottlenecks
    - Code clarity and documentation
    - Error handling
    - Test coverage
  </review_criteria>
  
  <output_format>
    For each issue found:
    - Severity: [Critical/High/Medium/Low]
    - Location: [Line numbers]
    - Description: [Clear explanation]
    - Suggestion: [How to fix]
  </output_format>
</code_review>
```

### 8.3 Creative Writing Template

```xml
<creative_task>
  <genre>Technical blog post</genre>
  
  <audience>
    Developers with 2-5 years experience
  </audience>
  
  <constraints>
    - Length: 800-1000 words
    - Tone: Informative but conversational
    - Include: 2-3 code examples
    - Avoid: Excessive jargon
  </constraints>
  
  <topic>
    [Your topic here]
  </topic>
  
  <structure>
    1. Hook (compelling opening)
    2. Problem statement
    3. Solution explanation with examples
    4. Best practices
    5. Call to action
  </structure>
</creative_task>
```

---

## 9. Cross-Model Compatibility

### 9.1 Universal Principles

These work across Claude, GPT-4, Gemini, and other major LLMs:

- Clear context and objectives
- Structured input (XML, JSON, or markdown)
- Few-shot examples for complex patterns
- Step-by-step reasoning instructions

### 9.2 Model-Specific Adaptations

#### Claude 4

- XML tags strongly preferred
- Thinking tags and keywords
- Style matching behavior
- 200K context window

#### GPT-4

- System/User message separation
- JSON mode available
- Function calling syntax differs
- 128K context window

#### Gemini

- Prefers concise prompts
- Strong multimodal capabilities
- Different safety thresholds
- Variable context windows

---

## 10. Quick Reference

### Essential Rules Checklist

- [ ] Be explicit and specific about requirements
- [ ] Use XML tags for structure (Claude preferred)
- [ ] Place important instructions at start/end
- [ ] Provide positive instructions (do vs. don't)
- [ ] Include examples for complex formats
- [ ] Match prompt style to desired output style
- [ ] Use appropriate thinking depth keywords
- [ ] Assign roles for specialized outputs
- [ ] Manage context window efficiently
- [ ] Optimize for caching and costs

### Common Patterns

**For Analysis:**

```xml
<thinking>Analyze step by step</thinking>
<answer>Final conclusion</answer>
```

**For Structured Output:**

```xml
<output_format>
  <json_schema>{your schema}</json_schema>
</output_format>
```

**For Iteration:**

```xml
<reflect>Consider the results</reflect>
<plan>Next steps based on findings</plan>
<execute>Take action</execute>
```

### Keywords and Special Tokens

- **Thinking Depth:** `think`, `think hard`, `think harder`, `ultrathink`
- **Structure:** `<thinking>`, `<answer>`, `<task>`, `<context>`
- **Workflow:** Explore → Plan → Code → Commit
- **TDD:** Test → Fail → Implement → Pass

---

## 💡 Pro Tips

1. **Iterate and Refine:** Don't expect perfection on first try
2. **Version Control:** Save effective prompts for reuse
3. **A/B Testing:** Compare different approaches systematically
4. **Monitor Costs:** Track token usage and optimize accordingly
5. **Stay Updated:** Model capabilities evolve rapidly

---

## 📚 Resources

- [Anthropic Official Documentation](https://docs.anthropic.com)
- [Claude API Reference](https://docs.anthropic.com/en/api)
- Community forums and GitHub discussions
- Academic papers on prompt engineering

---

*Last updated: June 2025. This guide reflects current best practices and will evolve with model updates.*
