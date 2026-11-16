import { createFileRoute } from "@tanstack/react-router";
import { getWsAskPage } from "@/lib/workspace-ask.functions";
import { WorkspaceAskPage } from "@/components/workspace/WorkspaceAskPage";

export const Route = createFileRoute("/w/$slug_/ask")({
  loader: ({ params }) => getWsAskPage({ data: { slug: params.slug } }),
  head: ({ params }) => {
    const title = `Stel een anonieme vraag aan ${params.slug} | ROUT`;
    const description = "Stel anoniem een vraag. Je vraag wordt in je eigen browser versleuteld; alleen de beheerders kunnen ze lezen.";
    return {
      meta: [
        { title },
        { name: "description", content: description },
        { property: "og:title", content: title },
        { property: "og:description", content: description },
        { property: "og:type", content: "website" },
        { name: "twitter:card", content: "summary" },
      ],
    };
  },
  component: () => <WorkspaceAskPage data={Route.useLoaderData()} slug={Route.useParams().slug} />,
});
