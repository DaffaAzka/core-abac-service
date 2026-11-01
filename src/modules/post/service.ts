import type { CreatePostBody, UpdatePostBody, PostItem } from "./model";

// In-memory backing store for demonstration (easily swappable to Prisma model)
const posts = new Map<string, PostItem>([
  [
    "1",
    {
      id: "1",
      title: "Welcome to Elysia and CASL",
      content: "This post is public and readable by anyone with read:Post permission.",
      authorId: "system",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ],
  [
    "2",
    {
      id: "2",
      title: "Attribute-Based Access Control Guide",
      content: "Only the author of this post can update it unless admin.",
      authorId: "author-alice",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ],
]);

/**
 * Decoupled business logic service for Posts.
 */
export abstract class PostService {
  static async list(): Promise<PostItem[]> {
    return Array.from(posts.values());
  }

  static async findById(id: string): Promise<PostItem | null> {
    const post = posts.get(id);
    return post ? { ...post } : null;
  }

  static async create(authorId: string, data: CreatePostBody): Promise<PostItem> {
    const post: PostItem = {
      id: crypto.randomUUID(),
      title: data.title,
      content: data.content,
      authorId,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    posts.set(post.id, post);
    return post;
  }

  static async update(id: string, data: UpdatePostBody): Promise<PostItem | null> {
    const existing = posts.get(id);
    if (!existing) return null;

    const updated: PostItem = {
      ...existing,
      title: data.title ?? existing.title,
      content: data.content ?? existing.content,
      updatedAt: new Date(),
    };
    posts.set(id, updated);
    return updated;
  }

  static async delete(id: string): Promise<boolean> {
    return posts.delete(id);
  }
}
