import { Elysia } from "elysia";
import { PostModel } from "./model";
import { PostService } from "./service";
import { subject, ForbiddenError, type AccessPlugin } from "../access";

/**
 * Post Controller factory (Elysia instance as controller).
 * Showcases:
 * 1. Type-level permission checking: `can: ["read", "Post"]`
 * 2. Instance-level ABAC authorization: `authorId === user.id`
 * 3. Individual ACL overrides: resource-specific grants and denials
 */
export const createPostController = (accessPlugin: AccessPlugin) =>
  new Elysia({ prefix: "/posts" })
    .use(accessPlugin)
    // List all posts (Protected by RBAC: requires read Post permission)
    .get(
      "/",
      async () => {
        return PostService.list();
      },
      {
        can: ["read", "Post"],
        response: {
          200: PostModel.postList,
        },
        detail: {
          tags: ["Posts"],
          summary: "List all posts (Viewer, Editor, or Admin role required)",
        },
      }
    )

    // Get single post by id
    .get(
      "/:id",
      async ({ params: { id }, status }) => {
        const post = await PostService.findById(id);
        if (!post) {
          return status(404, { error: "NotFound", message: "Post not found" });
        }
        return post;
      },
      {
        can: ["read", "Post"],
        response: {
          200: PostModel.post,
          404: PostModel.errorResponse,
        },
        detail: {
          tags: ["Posts"],
          summary: "Get post details by ID",
        },
      }
    )

    // Create new post
    .post(
      "/",
      async ({ body, principal }) => {
        return PostService.create(principal!.id, body);
      },
      {
        auth: true,
        can: ["create", "Post"],
        body: PostModel.createPostBody,
        response: {
          200: PostModel.post,
        },
        detail: {
          tags: ["Posts"],
          summary: "Create a new post (Editor or Admin required)",
        },
      }
    )

    // Update post (ABAC: Evaluates authorId === user.id via CASL condition)
    .patch(
      "/:id",
      async ({ params: { id }, body, ability, status }) => {
        const post = await PostService.findById(id);
        if (!post) {
          return status(404, { error: "NotFound", message: "Post not found" });
        }

        // CASL checks conditions: authorId: "${user.id}"
        // Throws ForbiddenError (transformed into 403 Forbidden) if user is not author or admin
        ForbiddenError.from(ability).throwUnlessCan("update", subject("Post", post));

        const updated = await PostService.update(id, body);
        return updated!;
      },
      {
        auth: true,
        body: PostModel.updatePostBody,
        response: {
          200: PostModel.post,
          404: PostModel.errorResponse,
        },
        detail: {
          tags: ["Posts"],
          summary: "Update a post (ABAC: only the author or Admin can update)",
        },
      }
    )

    // Delete post
    .delete(
      "/:id",
      async ({ params: { id }, ability, status }) => {
        const post = await PostService.findById(id);
        if (!post) {
          return status(404, { error: "NotFound", message: "Post not found" });
        }

        ForbiddenError.from(ability).throwUnlessCan("delete", subject("Post", post));

        await PostService.delete(id);
        return { success: true, message: `Post ${id} deleted successfully` };
      },
      {
        auth: true,
        response: {
          200: PostModel.deleteResponse,
          404: PostModel.errorResponse,
        },
        detail: {
          tags: ["Posts"],
          summary: "Delete a post (ABAC/ACL: author, admin, or granted user)",
        },
      }
    );

