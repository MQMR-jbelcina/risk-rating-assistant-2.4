import ratingRules from "../rules/rating_rules.json";

export type RatingLevel =
  | "very_favorable"
  | "favorable"
  | "neutral"
  | "unfavorable"
  | "very_unfavorable"
  | "n_a"
  | "no_information_provided";

export interface EvaluationDetails {
  rating?: Exclude<RatingLevel, "very_unfavorable" | "n_a" | "no_information_provided">;
  satisfiedControls?: string[];
  missingControls: string[];
  incidentResponseElements?: string[];
  infoTechOverview?: string[];
  reason?: string;
}

export interface EvaluationContext {
  handlesPii: boolean;
  remoteWorkAllowed: boolean;
  softwareProvider: boolean;
  incidentElements: string[];
}

export interface EvaluationResult {
  rating: RatingLevel;
  details: EvaluationDetails | null;
  context: EvaluationContext;
}

type ControlStatus = {
  controlId: string;
  required: boolean;
  satisfied: boolean;
  text: string;
  tags: string[];
};

type ControlStatusMap = Record<string, ControlStatus>;

type Rules = typeof ratingRules;

type CrossSatisfactionRule = Rules["conditions"]["cross_satisfaction"][number];

const SOFTWARE_PROVIDER_KEYWORDS = [
  "software provider",
  "software development",
  "develops software",
  "developing software",
  "builds software",
  "provides software",
  "saas",
  "platform as a service",
  "application development"
];

const normalize = (text: string): string =>
  text
    .toLowerCase()
    .replace(/…/g, "...")
    .replace(/\s+/g, " ")
    .trim();

const statementPresent = (notes: string, statement: string): boolean => {
  if (!statement) {
    return false;
  }
  const normalizedStatement = normalize(statement);
  return normalizedStatement.length > 0 && notes.includes(normalizedStatement);
};

const buildContext = (notes: string, rules: Rules) => {
  const logicalConditions = rules.conditions.logical_access_controls ?? {};
  const handlesPii = Boolean(
    logicalConditions.pii_positive_statements?.some((statement) =>
      statementPresent(notes, statement)
    )
  );

  const remoteCondition = rules.conditions.remote_workforce?.enforce_only_if_remote_work_allowed ?? "";
  const remoteWorkAllowed = Boolean(remoteCondition) && statementPresent(notes, remoteCondition);

  const softwareProvider = SOFTWARE_PROVIDER_KEYWORDS.some((phrase) =>
    notes.includes(phrase)
  );

  return { handlesPii, remoteWorkAllowed, softwareProvider };
};

const applyCrossSatisfaction = (notes: string, rules: Rules): Set<string> => {
  const satisfied = new Set<string>();
  const crossRules = rules.conditions.cross_satisfaction ?? [];
  crossRules.forEach((rule: CrossSatisfactionRule) => {
    const triggerStatements = rule.if_any_statement_present ?? [];
    if (
      triggerStatements.some((statement) => statementPresent(notes, statement))
    ) {
      rule.then_mark_controls_met?.forEach((controlId) => satisfied.add(controlId));
    }
  });
  return satisfied;
};

const statementSatisfiesControl = (
  notes: string,
  controlId: string,
  controlText: string,
  rules: Rules
): boolean => {
  if (statementPresent(notes, controlText)) {
    return true;
  }
  if (controlId && notes.includes(controlId)) {
    return true;
  }
  const words = controlId.split(/\W+/).filter(Boolean);
  if (words.length > 1) {
    const token = words.slice(1).join(" ");
    if (token && notes.includes(token)) {
      return true;
    }
  }

  if (controlId === "lac_passwords_encrypted_in_transit") {
    const negatives =
      rules.conditions.logical_access_controls
        ?.passwords_encrypted_in_transit_only_if_negative_statement_present ?? [];
    if (negatives.some((statement) => statementPresent(notes, statement))) {
      return false;
    }
  }

  return false;
};

const registerControl = (
  status: ControlStatusMap,
  controlId: string,
  required: boolean,
  satisfied: boolean,
  text: string,
  tags: string[]
) => {
  status[controlId] = { controlId, required, satisfied, text, tags };
};

const evaluateControls = (
  notes: string,
  rules: Rules,
  context: ReturnType<typeof buildContext>,
  crossSatisfied: Set<string>
): ControlStatusMap => {
  const status: ControlStatusMap = {};
  const catalog = rules.catalog ?? {};
  const conditions = rules.conditions ?? {};

  const checkControl = (control: any, required: boolean = true) => {
    const controlId = control.id as string;
    const controlText = (control.text ?? "") as string;
    const tags = (control.tags ?? []) as string[];
    const satisfied = crossSatisfied.has(controlId)
      ? true
      : statementSatisfiesControl(notes, controlId, controlText, rules);
    registerControl(status, controlId, required, satisfied, controlText, tags);
  };

  catalog.logical_access_controls?.forEach((control: any) => {
    let required = true;
    if (
      control.id === "lac_mfa_critical_or_pii" &&
      conditions.logical_access_controls?.enforce_mfa_critical_or_pii_if_company_handles_pii &&
      !context.handlesPii
    ) {
      required = false;
    }
    checkControl(control, required);
  });

  const networkCatalog = catalog.network_information_security ?? {};

  networkCatalog.pii_controls?.forEach((control: any) => {
    let required = true;
    if (
      conditions.network_information_security?.enforce_pii_controls_if_company_handles_pii &&
      !context.handlesPii
    ) {
      required = false;
    }
    if (
      control.id === "net_pii_need_to_know" &&
      conditions.network_information_security?.do_not_enforce_need_to_know_if_least_privilege_statement_present
    ) {
      const leastPrivilege = status["lac_least_privilege"];
      if (leastPrivilege?.satisfied) {
        registerControl(status, control.id, false, true, control.text ?? "", control.tags ?? []);
        return;
      }
    }
    checkControl(control, required);
  });

  networkCatalog.controls?.forEach((control: any) => {
    checkControl(control, true);
  });

  catalog.change_mgmt_sdlc?.forEach((control: any) => {
    const required = context.softwareProvider;
    checkControl(control, required);
  });

  catalog.remote_workforce?.forEach((control: any) => {
    const required = context.remoteWorkAllowed;
    checkControl(control, required);
  });

  catalog.business_continuity?.forEach((control: any) => {
    checkControl(control, true);
  });

  return status;
};

const collectIncidentResponseElements = (
  notes: string,
  rules: Rules
): Set<string> => {
  const elements = new Set<string>();
  rules.catalog.incident_response_elements?.forEach((element) => {
    if (statementPresent(notes, element)) {
      elements.add(element);
    }
  });
  return elements;
};

const evaluateInfoTechOverview = (notes: string, rules: Rules): Set<string> => {
  const required =
    rules.ratings.very_favorable.info_tech_overview?.required ?? [];
  const present = new Set<string>();
  required.forEach((statement) => {
    if (statementPresent(notes, statement)) {
      present.add(statement);
    }
  });
  return present;
};

const evaluateBusinessContinuity = (status: ControlStatusMap): boolean => {
  const bcpControl = status["bcp_plan"];
  return Boolean(bcpControl?.satisfied);
};

const categoryControls = (
  prefix: string,
  status: ControlStatusMap
): ControlStatus[] => Object.values(status).filter((ctrl) => ctrl.controlId.startsWith(prefix));

const meetsInfoTechOverview = (requirement: any, present: Set<string>): boolean => {
  const required = requirement?.required ?? [];
  return required.every((statement: string) => present.has(statement));
};

const meetsLogicalAccessControls = (requirement: any, status: ControlStatusMap): boolean => {
  const controls = categoryControls("lac_", status).filter((ctrl) => ctrl.required);
  if (requirement?.required_all) {
    return controls.every((ctrl) => ctrl.satisfied);
  }
  const count = controls.filter((ctrl) => ctrl.satisfied).length;
  if (count < (requirement?.min_count ?? 0)) {
    return false;
  }
  const tag = requirement?.must_include_tag as string | undefined;
  if (tag) {
    const hasTagged = controls.some((ctrl) => ctrl.satisfied && ctrl.tags.includes(tag));
    if (!hasTagged) {
      return false;
    }
  }
  return true;
};

const meetsNetworkControls = (
  requirement: any,
  context: ReturnType<typeof buildContext>,
  status: ControlStatusMap
): boolean => {
  const piiControls = categoryControls("net_pii_", status).filter((ctrl) => ctrl.required);
  if (requirement?.pii_controls_required_if_company_handles_pii && context.handlesPii) {
    if (!piiControls.length || piiControls.some((ctrl) => !ctrl.satisfied)) {
      return false;
    }
  }
  const netControls = Object.values(status).filter(
    (ctrl) => ctrl.controlId.startsWith("net_") && !ctrl.controlId.startsWith("net_pii_")
  );
  const requiredControls = netControls.filter((ctrl) => ctrl.required);
  if (requirement?.controls_required_all) {
    return requiredControls.every((ctrl) => ctrl.satisfied);
  }
  const count = requiredControls.filter((ctrl) => ctrl.satisfied).length;
  if (count < (requirement?.min_count ?? 0)) {
    return false;
  }
  const tag = requirement?.must_include_tag as string | undefined;
  if (tag) {
    const hasTagged = requiredControls.some(
      (ctrl) => ctrl.satisfied && ctrl.tags.includes(tag)
    );
    if (!hasTagged) {
      return false;
    }
  }
  return true;
};

const meetsChangeMgmt = (
  requirement: any,
  context: ReturnType<typeof buildContext>,
  status: ControlStatusMap
): boolean => {
  const controls = categoryControls("chg_", status).filter((ctrl) => ctrl.required);
  if (!context.softwareProvider) {
    return true;
  }
  if (requirement?.required_all) {
    return controls.every((ctrl) => ctrl.satisfied);
  }
  if (requirement?.require_change_mgmt_process) {
    const changeMgmt = status["chg_change_mgmt_process"];
    if (!changeMgmt?.satisfied) {
      return false;
    }
  }
  const minCountFrom = requirement?.min_count_from as string[] | undefined;
  if (minCountFrom?.length) {
    const satisfiedCount = minCountFrom.reduce((count, controlId) => {
      const control = status[controlId];
      return control?.satisfied ? count + 1 : count;
    }, 0);
    return satisfiedCount >= (requirement?.min_count ?? 0);
  }
  const count = controls.filter((ctrl) => ctrl.satisfied).length;
  return count >= (requirement?.min_count ?? 0);
};

const meetsRemoteWorkforce = (
  requirement: any,
  context: ReturnType<typeof buildContext>,
  status: ControlStatusMap
): boolean => {
  const controls = categoryControls("rw_", status).filter((ctrl) => ctrl.required);
  if (!context.remoteWorkAllowed) {
    return true;
  }
  if (requirement?.required_all) {
    return controls.every((ctrl) => ctrl.satisfied);
  }
  const count = controls.filter((ctrl) => ctrl.satisfied).length;
  return count >= (requirement?.min_count ?? 0);
};

const meetsIncidentResponse = (requirement: any, elements: Set<string>): boolean => {
  const minElements = requirement?.min_elements;
  if (typeof minElements !== "number") {
    return true;
  }
  return elements.size >= minElements;
};

const meetsBusinessContinuity = (requirement: any, hasPlan: boolean): boolean => {
  if (!requirement) {
    return true;
  }
  if (requirement.required && !hasPlan) {
    return false;
  }
  return true;
};

const missingRequiredControls = (status: ControlStatusMap): string[] => {
  return Object.values(status)
    .filter((ctrl) => ctrl.required && !ctrl.satisfied)
    .map((ctrl) => ctrl.controlId)
    .sort();
};

const buildRatingDetails = (
  rating: Exclude<RatingLevel, "very_unfavorable" | "n_a" | "no_information_provided">,
  status: ControlStatusMap,
  incidentElements: Set<string>,
  infoTechOverview: Set<string>
): EvaluationDetails => ({
  rating,
  satisfiedControls: Object.values(status)
    .filter((ctrl) => ctrl.required && ctrl.satisfied)
    .map((ctrl) => ctrl.controlId)
    .sort(),
  missingControls: missingRequiredControls(status),
  incidentResponseElements: Array.from(incidentElements).sort(),
  infoTechOverview: Array.from(infoTechOverview).sort()
});

const determineRating = (
  rules: Rules,
  context: ReturnType<typeof buildContext>,
  status: ControlStatusMap,
  incidentElements: Set<string>,
  infoTechOverview: Set<string>,
  businessContinuity: boolean
): { rating: RatingLevel; details: EvaluationDetails | null } => {
  const ratingsOrder: Exclude<RatingLevel, "very_unfavorable" | "n_a" | "no_information_provided">[] = [
    "very_favorable",
    "favorable",
    "neutral",
    "unfavorable"
  ];

  for (const rating of ratingsOrder) {
    const requirements = (rules.ratings as any)[rating];
    if (
      meetsInfoTechOverview(requirements.info_tech_overview, infoTechOverview) &&
      meetsLogicalAccessControls(requirements.logical_access_controls, status) &&
      meetsNetworkControls(requirements.network_information_security, context, status) &&
      meetsChangeMgmt(requirements.change_mgmt_sdlc, context, status) &&
      meetsRemoteWorkforce(requirements.remote_workforce, context, status) &&
      meetsIncidentResponse(requirements.incident_response, incidentElements) &&
      meetsBusinessContinuity(requirements.business_continuity, businessContinuity)
    ) {
      return {
        rating,
        details: buildRatingDetails(rating, status, incidentElements, infoTechOverview)
      };
    }
  }

  return {
    rating: "very_unfavorable",
    details: {
      missingControls: missingRequiredControls(status),
      reason:
        "Vendor did not satisfy the minimum safeguards for an unfavorable rating."
    }
  };
};

export const evaluateNotes = (rawNotes: string): EvaluationResult => {
  const normalizedNotes = normalize(rawNotes ?? "");
  if (!normalizedNotes) {
    return {
      rating: "no_information_provided",
      details: null,
      context: {
        handlesPii: false,
        remoteWorkAllowed: false,
        softwareProvider: false,
        incidentElements: []
      }
    };
  }

  if (
    normalizedNotes.includes("not applicable") ||
    /\bn\/a\b/.test(normalizedNotes)
  ) {
    return {
      rating: "n_a",
      details: null,
      context: {
        handlesPii: false,
        remoteWorkAllowed: false,
        softwareProvider: false,
        incidentElements: []
      }
    };
  }

  const context = buildContext(normalizedNotes, ratingRules);
  const crossSatisfied = applyCrossSatisfaction(normalizedNotes, ratingRules);
  const controlStatus = evaluateControls(
    normalizedNotes,
    ratingRules,
    context,
    crossSatisfied
  );
  const incidentElements = collectIncidentResponseElements(
    normalizedNotes,
    ratingRules
  );
  const infoTechOverview = evaluateInfoTechOverview(normalizedNotes, ratingRules);
  const businessContinuity = evaluateBusinessContinuity(controlStatus);

  const { rating, details } = determineRating(
    ratingRules,
    context,
    controlStatus,
    incidentElements,
    infoTechOverview,
    businessContinuity
  );

  return {
    rating,
    details,
    context: {
      handlesPii: context.handlesPii,
      remoteWorkAllowed: context.remoteWorkAllowed,
      softwareProvider: context.softwareProvider,
      incidentElements: Array.from(incidentElements).sort()
    }
  };
};
