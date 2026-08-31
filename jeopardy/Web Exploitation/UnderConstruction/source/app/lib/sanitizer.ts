import DOMPurify from 'isomorphic-dompurify';

export const sanitizer = (input: string): string => {
  return DOMPurify.sanitize(input, {
    ALLOWED_TAGS: ['h1', 'h2', 'h3', 'p', 'b', 'i', 'u', 'strong', 'em', 'br', 'img', 'a'],
    ALLOWED_ATTR: ['src', 'alt', 'href'],
  });
};
