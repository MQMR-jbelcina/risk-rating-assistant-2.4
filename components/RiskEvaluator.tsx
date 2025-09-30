"use client";

import type { ReactNode } from "react";
import { useMemo, useState } from "react";
import { evaluateNotes, EvaluationResult } from "../lib/evaluator";

type RiskEvaluatorProps = {
  initialNotes?: string;
};

const ratingLabels: Record<string, string> = {
  very_favorable: "Very Favorable",
  favorable: "Favorable",
  neutral: "Neutral",
  unfavorable: "Unfavorable",
  very_unfavorable: "Very Unfavorable",
  n_a: "Not Applicable",
  no_information_provided: "No Information Provided"
};

const badgeClassNames: Record<string, string> = {
  very_favorable: "bg-emerald-100 text-emerald-900 border-emerald-200",
  favorable: "bg-green-100 text-green-900 border-green-200",
  neutral: "bg-slate-100 text-slate-900 border-slate-200",
  unfavorable: "bg-amber-100 text-amber-900 border-amber-200",
  very_unfavorable: "bg-red-100 text-red-900 border-red-200",
  n_a: "bg-blue-100 text-blue-900 border-blue-200",
  no_information_provided: "bg-gray-100 text-gray-900 border-gray-200"
};

const SectionTitle = ({ children }: { children: ReactNode }) => (
  <h2 className="text-lg font-semibold text-slate-800 mb-2">{children}</h2>
);

const Section = ({ children }: { children: ReactNode }) => (
  <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
    {children}
  </section>
);

const DescriptionList = ({
  title,
  items
}: {
  title: string;
  items: string[];
}) => (
  <div>
    <h3 className="font-medium text-slate-700 mb-1">{title}</h3>
    {items.length ? (
      <ul className="list-disc list-inside text-sm text-slate-600 space-y-1">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    ) : (
      <p className="text-sm text-slate-500">None</p>
    )}
  </div>
);

const formatMultiline = (text: string) => text.replace(/\r?\n/g, "\n");

export default function RiskEvaluator({ initialNotes = "" }: RiskEvaluatorProps) {
  const [notes, setNotes] = useState(formatMultiline(initialNotes));
  const [result, setResult] = useState<EvaluationResult | null>(() =>
    initialNotes ? evaluateNotes(initialNotes) : null
  );

  const handleEvaluate = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setResult(evaluateNotes(notes));
  };

  const handleReset = () => {
    setNotes(initialNotes ?? "");
    setResult(initialNotes ? evaluateNotes(initialNotes) : null);
  };

  const summary = useMemo(() => {
    if (!result) {
      return null;
    }
    const label = ratingLabels[result.rating];
    const badgeClass = badgeClassNames[result.rating] ?? badgeClassNames.neutral;
    return (
      <div className="flex flex-col gap-4">
        <div className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-semibold ${badgeClass}`}>
          <span>Rating:</span>
          <span>{label}</span>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Section>
            <SectionTitle>Context</SectionTitle>
            <dl className="space-y-2 text-sm text-slate-600">
              <div className="flex justify-between">
                <dt>Handles PII</dt>
                <dd className="font-medium text-slate-900">
                  {result.context.handlesPii ? "Yes" : "No"}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt>Remote Work Allowed</dt>
                <dd className="font-medium text-slate-900">
                  {result.context.remoteWorkAllowed ? "Yes" : "No"}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt>Software Provider</dt>
                <dd className="font-medium text-slate-900">
                  {result.context.softwareProvider ? "Yes" : "No"}
                </dd>
              </div>
              <div>
                <dt className="text-slate-700 font-medium">Incident Response Elements</dt>
                {result.context.incidentElements.length ? (
                  <ul className="list-disc list-inside text-slate-600">
                    {result.context.incidentElements.map((element) => (
                      <li key={element}>{element}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-slate-500">None detected</p>
                )}
              </div>
            </dl>
          </Section>
          <Section>
            <SectionTitle>Details</SectionTitle>
            {result.details ? (
              <div className="space-y-3">
                {result.details.reason && (
                  <p className="text-sm text-slate-600">{result.details.reason}</p>
                )}
                {result.details.satisfiedControls && (
                  <DescriptionList
                    title="Satisfied Controls"
                    items={result.details.satisfiedControls}
                  />
                )}
                <DescriptionList
                  title="Missing Controls"
                  items={result.details.missingControls ?? []}
                />
                {result.details.infoTechOverview && (
                  <DescriptionList
                    title="Info Tech Overview"
                    items={result.details.infoTechOverview}
                  />
                )}
                {result.details.incidentResponseElements && (
                  <DescriptionList
                    title="Incident Response Elements"
                    items={result.details.incidentResponseElements}
                  />
                )}
              </div>
            ) : (
              <p className="text-sm text-slate-500">
                No additional control details for this rating.
              </p>
            )}
          </Section>
        </div>
      </div>
    );
  }, [result]);

  return (
    <div className="space-y-6">
      <form onSubmit={handleEvaluate} className="space-y-4">
        <div className="space-y-2">
          <label htmlFor="notes" className="text-sm font-medium text-slate-700">
            Analyst Notes
          </label>
          <textarea
            id="notes"
            className="w-full min-h-[220px] resize-y rounded-lg border border-slate-300 p-3 text-sm shadow-sm focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-200"
            value={notes}
            onChange={(event) => setNotes(event.target.value)}
            placeholder="Paste analyst notes here..."
          />
        </div>
        <div className="flex flex-wrap gap-3">
          <button
            type="submit"
            className="inline-flex items-center justify-center rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-400"
          >
            Evaluate Vendor
          </button>
          <button
            type="button"
            onClick={handleReset}
            className="inline-flex items-center justify-center rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-slate-200"
          >
            Reset to Sample
          </button>
        </div>
      </form>
      {summary}
    </div>
  );
}
