import { describe, expect, it } from "bun:test";
import { app } from "./index";

describe("Elysia Feature Controllers Integration", () => {
  it("GET / returns root API metadata", async () => {
    const res = await app.handle(new Request("http://localhost/"));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.name).toBe("Find Cat Elysia API");
    expect(body.modules.auth).toBe("/auth");
    expect(body.modules.posts).toBe("/posts");
  });

  it("GET /health returns health check", async () => {
    const res = await app.handle(new Request("http://localhost/health"));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("ok");
  });

  it("GET /posts allows anonymous read (viewer role)", async () => {
    const res = await app.handle(new Request("http://localhost/posts"));
    expect(res.status).toBe(200);
    const posts = await res.json();
    expect(Array.isArray(posts)).toBe(true);
    expect(posts.length).toBeGreaterThan(0);
  });

  it("POST /posts requires authentication (401)", async () => {
    const res = await app.handle(
      new Request("http://localhost/posts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "New Post",
          content: "Post content",
        }),
      })
    );
    expect(res.status).toBe(401);
  });

  it("GET /users/me requires authentication (401)", async () => {
    const res = await app.handle(new Request("http://localhost/users/me"));
    expect(res.status).toBe(401);
  });

  it("GET /access/roles requires admin manage permission (403)", async () => {
    const res = await app.handle(new Request("http://localhost/access/roles"));
    expect(res.status).toBe(403);
  });
});
