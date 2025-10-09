"use client";

import { FormEvent, useEffect, useState } from "react";

const navItems = [
  { label: "Solutions", href: "#solutions" },
  { label: "Work", href: "#work" },
  { label: "Process", href: "#process" },
  { label: "About", href: "#about" },
  { label: "Contact", href: "#contact" }
];

const projects = [
  {
    id: "chatbot",
    title: "AI Support Copilot",
    description:
      "Fine-tuned GPT-4.1 assistant with retrieval that drafts empathetic responses from the team's knowledge base and enforces tone guardrails.",
    result: "-38% resolution time",
    tech: "Stack: Next.js • Supabase • OpenAI Functions",
    meta: "AI chatbot",
    year: "2024"
  },
  {
    id: "telegram-notion",
    title: "Telegram → Notion Automations",
    description:
      "Real-time sync that captures community requests from Telegram, enriches with embeddings, and routes insights into a Notion CRM dashboard.",
    result: "+14 hrs saved / week",
    tech: "Stack: Cloudflare Workers • LangChain • Notion API",
    meta: "Workflow ops",
    year: "2024"
  },
  {
    id: "scheduler",
    title: "AI Appointment Setter",
    description:
      "Voice + email agent that coordinates calendars, triages leads, and books intro calls autonomously while logging outcomes back to HubSpot.",
    result: "2× qualified bookings",
    tech: "Stack: VAPI • Calendly • HubSpot • GPT-4o",
    meta: "Agentic ops",
    year: "2025"
  }
];

const processSteps = [
  {
    icon: "🔍",
    title: "Discover",
    description: "Audit your workflows, tools, and constraints to surface the high-leverage automation opportunities.",
    badge: "01"
  },
  {
    icon: "🛠️",
    title: "Design & Build",
    description: "Prototype, test, and harden AI-powered automations with developer-grade reliability and observability.",
    badge: "02"
  },
  {
    icon: "🚀",
    title: "Deploy & Coach",
    description: "Launch with clear playbooks, success metrics, and async coaching so the team knows exactly how to operate the system.",
    badge: "03"
  }
];

const heroCodeSample = `// JiwonAI Automation Pipeline
const pipeline = createWorkflow({
  triggers: ["telegram:new-message", "cal.com:booking"],
  ai: {
    model: "gpt-4.1-mini",
    retrieval: true,
    guardrails: ["tone", "sla"]
  },
  actions: [
    "notion.appendPage",
    "slack.notify#ops",
    "calendar.schedule"
  ]
});

ship(pipeline).onSuccess(team => {
  team.hoursSaved = 18; // weekly
});`;

function SunIcon() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24" strokeWidth="1.6" stroke="currentColor">
      <circle cx="12" cy="12" r="4.5" />
      <path d="M12 2v2.4M12 19.6V22M4.4 4.4l1.7 1.7M17.9 17.9l1.7 1.7M2 12h2.4M19.6 12H22M4.4 19.6l1.7-1.7M17.9 6.1l1.7-1.7" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24" strokeWidth="1.6" stroke="currentColor">
      <path
        d="M20.5 14.2A8.3 8.3 0 0 1 9.8 3.5a6.4 6.4 0 1 0 10.7 10.7Z"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function HomePage() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem("jiwonai-theme");
      if (stored === "light" || stored === "dark") {
        setTheme(stored);
        return;
      }
      if (window.matchMedia("(prefers-color-scheme: light)").matches) {
        setTheme("light");
      }
    } catch (error) {
      console.warn("Theme preference unavailable", error);
    }
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = theme;
    root.style.setProperty("color-scheme", theme);
    try {
      window.localStorage.setItem("jiwonai-theme", theme);
    } catch (error) {
      console.warn("Unable to persist theme", error);
    }
  }, [theme]);

  useEffect(() => {
    const elements = Array.from(document.querySelectorAll<HTMLElement>(".reveal"));
    if (elements.length === 0) {
      return;
    }

    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion || typeof IntersectionObserver === "undefined") {
      elements.forEach((element) => element.classList.add("is-visible"));
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.18, rootMargin: "0px 0px -10% 0px" }
    );

    elements.forEach((element) => observer.observe(element));

    return () => {
      elements.forEach((element) => observer.unobserve(element));
      observer.disconnect();
    };
  }, []);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    form.reset();
    setSubmitted(true);
  };

  const toggleTheme = () => {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  };

  const themeLabel = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
  const currentYear = new Date().getFullYear();

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <div className="page">
        <header className="top-nav">
          <div className="brand">
            <span aria-hidden="true" className="brand-mark">
              JA
            </span>
            <span>JiwonAI</span>
          </div>
          <nav aria-label="Primary" className="nav-links">
            {navItems.map((item) => (
              <a key={item.href} href={item.href}>
                {item.label}
              </a>
            ))}
          </nav>
          <button
            type="button"
            className="theme-toggle"
            aria-pressed={theme === "light"}
            aria-label={themeLabel}
            onClick={toggleTheme}
          >
            {theme === "dark" ? <SunIcon /> : <MoonIcon />}
            <span>{theme === "dark" ? "Light" : "Dark"}</span>
          </button>
        </header>

        <main id="main">
          <section className="section hero reveal" id="hero">
            <div className="hero-content">
              <p className="section-kicker">AI &amp; automation consultant</p>
              <h1 className="hero-tagline">
                Automate your business with <span className="gradient-text">AI.</span>
              </h1>
              <p className="hero-subtitle">
                JiwonAI builds developer-grade automations that let lean teams ship faster, delight
                customers, and stay laser-focused on high-leverage work.
              </p>
              <div className="hero-actions">
                <a className="button button-primary" href="#contact">
                  Start a project
                </a>
                <a className="button button-secondary" href="#work">
                  Explore automations
                </a>
              </div>
              <div className="hero-badges">
                <span className="badge">⚡ 40+ hrs saved per founder</span>
                <span className="badge">🤝 Fractional CTO partnership</span>
                <span className="badge">🛡️ Privacy-first, auditable AI</span>
              </div>
            </div>
            <div className="hero-visual" aria-hidden="true">
              <div className="hero-console">
                <div className="hero-console-header">
                  <div className="hero-console-dots">
                    <span />
                    <span />
                    <span />
                  </div>
                  <span>workflow.ts</span>
                </div>
                <pre className="hero-console-code">{heroCodeSample}</pre>
              </div>
            </div>
          </section>

          <section className="section reveal" id="solutions">
            <div className="section-header">
              <p className="section-kicker">Problem → Solution</p>
              <h2 className="section-title">Ship automations that actually stick</h2>
              <p className="section-description">
                JiwonAI partners with small and mighty teams to remove the rote work holding them back.
                Every workflow is designed, tested, and documented like a product—because it is.
              </p>
            </div>
            <div className="problem-solution-grid">
              <article className="problem-card" aria-label="Problems JiwonAI solves">
                <h3>The problem</h3>
                <ul>
                  <li>Manual updates between tools slow down operations and create brittle handoffs.</li>
                  <li>Generic AI experiments never leave the prototype stage or earn stakeholder trust.</li>
                  <li>Teams lack observability, documentation, and ongoing coaching after launch.</li>
                </ul>
              </article>
              <article className="solution-card" aria-label="How JiwonAI solves it">
                <h3>The solution</h3>
                <ul>
                  <li>Developer-grade automations with logging, guardrails, and crisp operating docs.</li>
                  <li>AI copilots tuned to your data, tone, and compliance requirements.</li>
                  <li>Continuous optimization loops and async training so adoption sticks.</li>
                </ul>
              </article>
            </div>
          </section>

          <section className="section reveal" id="work">
            <div className="section-header">
              <p className="section-kicker">Showcase</p>
              <h2 className="section-title">Automation demos &amp; live systems</h2>
              <p className="section-description">
                Each build blends AI reasoning with robust automation tooling, tailored to your stack.
              </p>
            </div>
            <div className="projects-grid">
              {projects.map((project) => (
                <article className="project-card" key={project.id}>
                  <div className="project-meta">
                    <span>{project.meta}</span>
                    <span>{project.year}</span>
                  </div>
                  <h3 className="project-title">{project.title}</h3>
                  <p className="project-description">{project.description}</p>
                  <span className="project-result">{project.result}</span>
                  <p className="project-tech">{project.tech}</p>
                </article>
              ))}
            </div>
          </section>

          <section className="section reveal" id="process">
            <div className="section-header">
              <p className="section-kicker">How it works</p>
              <h2 className="section-title">A three-step path to automated operations</h2>
              <p className="section-description">
                From discovery to launch, the engagement is structured to prioritize velocity, reliability,
                and knowledge transfer.
              </p>
            </div>
            <div className="process-steps">
              {processSteps.map((step) => (
                <article className="process-step" data-step={step.badge} key={step.title}>
                  <div aria-hidden="true" className="step-icon">
                    {step.icon}
                  </div>
                  <h3>{step.title}</h3>
                  <p>{step.description}</p>
                </article>
              ))}
            </div>
          </section>

          <section className="section reveal" id="about">
            <div className="section-header">
              <p className="section-kicker">About</p>
              <h2 className="section-title">Meet Jonas Belcina</h2>
            </div>
            <div className="about-section">
              <article className="about-bio">
                <h3>Founder, JiwonAI</h3>
                <p>
                  Jonas is an AI &amp; automation consultant blending product strategy with full-stack
                  engineering. Before JiwonAI, he led automation at SaaS scale-ups, reducing manual ops by
                  double digits every quarter.
                </p>
                <p>
                  Today he partners with founders, COOs, and operations leaders to embed AI agents, data
                  pipelines, and custom workflows that scale with the team. Expect deep technical dives,
                  crisp documentation, and async-first collaboration.
                </p>
                <p className="signature">Jonas Belcina</p>
              </article>
              <aside className="about-portrait" aria-label="Illustration of Jonas Belcina">
                <div className="portrait-frame">
                  <span>Jonas Belcina — builder of friendly AI copilots for ambitious teams.</span>
                </div>
              </aside>
            </div>
          </section>

          <section className="section reveal" id="contact">
            <div className="cta-card">
              <div className="cta-content">
                <div>
                  <p className="section-kicker">Free workflow audit</p>
                  <h2 className="section-title">See where automation saves your team hours</h2>
                  <p className="section-description">
                    Drop a quick note about your team and we'll send a loom teardown with automation
                    recommendations in under 48 hours.
                  </p>
                  <ul className="cta-list">
                    <li>Personalized architecture suggestions</li>
                    <li>Process map highlighting AI leverage points</li>
                    <li>Delivery roadmap with clear next steps</li>
                  </ul>
                </div>
                <form className="form" onSubmit={handleSubmit}>
                  <div>
                    <label htmlFor="name">Name</label>
                    <input id="name" name="name" autoComplete="name" required placeholder="Your name" />
                  </div>
                  <div>
                    <label htmlFor="email">Work email</label>
                    <input
                      id="email"
                      name="email"
                      type="email"
                      autoComplete="email"
                      required
                      placeholder="you@company.com"
                    />
                  </div>
                  <div>
                    <label htmlFor="challenge">What should we automate?</label>
                    <textarea
                      id="challenge"
                      name="challenge"
                      placeholder="Share your current workflow or biggest bottleneck"
                      required
                    />
                  </div>
                  <button className="button button-primary" type="submit">
                    Request the audit
                  </button>
                  <p className="form-note">No spam—just one tailored loom and next steps.</p>
                  {submitted ? <p className="form-success">Thanks! Expect a reply within 24 hours.</p> : null}
                </form>
              </div>
            </div>
          </section>
        </main>

        <footer className="footer reveal">
          <p>© {currentYear} JiwonAI. Crafted for small teams around the globe.</p>
          <p>
            Say hello at <a href="mailto:jonas@jiwonai.com">jonas@jiwonai.com</a>
          </p>
        </footer>
      </div>
    </>
  );
}
