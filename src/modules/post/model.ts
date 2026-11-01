import { t } from "elysia";

export const PostModel = {
  post: t.Object({
    id: t.String(),
    title: t.String(),
    content: t.String(),
    authorId: t.String(),
    createdAt: t.Date(),
    updatedAt: t.Date(),
  }),

  postList: t.Array(
    t.Object({
      id: t.String(),
      title: t.String(),
      content: t.String(),
      authorId: t.String(),
      createdAt: t.Date(),
    })
  ),

  createPostBody: t.Object({
    title: t.String({ minLength: 3, maxLength: 200 }),
    content: t.String({ minLength: 1 }),
  }),

  updatePostBody: t.Object({
    title: t.Optional(t.String({ minLength: 3, maxLength: 200 })),
    content: t.Optional(t.String({ minLength: 1 })),
  }),

  deleteResponse: t.Object({
    success: t.Boolean(),
    message: t.String(),
  }),

  errorResponse: t.Object({
    error: t.String(),
    message: t.Optional(t.String()),
  }),
};

export type CreatePostBody = typeof PostModel.createPostBody.static;
export type UpdatePostBody = typeof PostModel.updatePostBody.static;
export type PostItem = typeof PostModel.post.static;
