import { createFileRoute } from "@tanstack/react-router";
import { getPublicWsSupport } from "@/lib/workspace-support.functions";
import { WorkspaceSupportPage } from "@/components/workspace/WorkspaceSupportPage";
import { profilePreviewPath } from "@/lib/profile-preview";

export const Route = createFileRoute("/w/$slug_/support")({
  loader: ({ params }) => getPublicWsSupport({ data: { slug: params.slug } }),
  head: ({ params }) => {
    const title = `Steun ${params.slug} | ROUT`;
    const description = "Steun deze werkruimte rechtstreeks op haar eigen rekening. ROUT verwerkt geen geld.";
    const image = `https://rout.be${profilePreviewPath(params.slug, "workspace")}`;
    return {
      meta: [
        { title },
        { name: "description", content: description },
        { property: "og:title", content: title },
        { property: "og:description", content: description },
        { property: "og:type", content: "website" },
        { property: "og:image", content: image },
        { name: "twitter:card", content: "summary_large_image" },
        { name: "twitter:image", content: image },
      ],
    };
  },
  component: () => <WorkspaceSupportPage page={Route.useLoaderData()} slug={Route.useParams().slug} />,
});
