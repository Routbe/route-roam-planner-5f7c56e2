import { createFileRoute, redirect } from "@tanstack/react-router";

/** /studio/agenda: the operational calendar dashboard lives at /agenda. */
export const Route = createFileRoute("/_authenticated/studio_/agenda")({
  beforeLoad: () => { throw redirect({ to: "/agenda", replace: true }); },
});
