const { AuthenticationError, UserInputError } = require("apollo-server");
const { Types } = require("mongoose");
const Post = require("../../models/Post");
const checkAuth = require("../../middlewares/check-auth");

module.exports = {
  Query: {
    async getPosts() {
      try {
        const posts = await Post.find().sort({ createdAt: -1 });
        return posts;
      } catch (err) {
        throw new Error(err);
      }
    },
    async getPost(_, { postId }) {
      if (!Types.ObjectId.isValid(postId)) {
        throw new Error("Invalid Post ID!");
      }
      try {
        const post = await Post.findById(postId);
        if (post) {
          return post;
        } else {
          throw new Error("Post Not Found!");
        }
      } catch (err) {
        throw new Error(err);
      }
    }
  },
  Mutation: {
    async createPost(_, { body }, context) {
      const user = checkAuth(context);

      if (body.trim() === "") throw new Error("Post body must not be empty!");

      const newPost = new Post({
        body,
        user: user.id,
        username: user.username,
        createdAt: new Date().toISOString()
      });

      const post = await newPost.save();

      context.pubsub.publish("NEW_POST", {
        newPost: post
      });
      return post;
    },
    async deletePost(_, { postId }, context) {
      const user = checkAuth(context);
      if (!Types.ObjectId.isValid(postId)) {
        throw new Error("Invalid Post ID!");
      }

      try {
        const post = await Post.findById(postId);
        if (!post) {
          throw new Error("Post Not Found!");
        }
        if (user.username === post.username) {
          await post.delete();
          return "Post Deleted Successfully!";
        } else {
          throw new AuthenticationError("Action is not Allowed!");
        }
      } catch (err) {
        throw new Error(err);
      }
    },
    async likePost(_, { postId }, context) {
      const { username } = checkAuth(context);

      const post = await Post.findById(postId);

      if (post) {
        if (post.likes.find(like => like.username === username)) {
          //post is liked, unlike it
          post.likes = post.likes.filter(like => like.username !== username);
        } else {
          //post is unliked, like it
          post.likes.push({
            username,
            createdAt: new Date().toISOString()
          });
        }
        await post.save();
        return post;
      } else throw new UserInputError("Post Not Found!");
    }
  },
  Subscription: {
    newPost: {
      subscribe: (_, __, { pubsub }) => pubsub.asyncIterator("NEW_POST")
    }
  }
};
