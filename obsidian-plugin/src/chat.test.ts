import { describe, expect, it, vi } from 'vitest';
import { ChatManager } from './chat';

describe('ChatManager', () => {
  it('removeMessage removes by id and triggers onUpdate', () => {
    const cm = new ChatManager();
    const updates: any[] = [];
    cm.onUpdate = (msgs) => updates.push([...msgs]);

    const a = ChatManager.createUserMessage('a');
    const b = ChatManager.createSystemMessage('b');
    cm.addMessage(a);
    cm.addMessage(b);

    cm.removeMessage(b.id);

    expect(cm.getMessages().length).toBe(1);
    expect(cm.getMessages()[0]?.id).toBe(a.id);
    expect(updates.length).toBe(1);
    expect(updates[0].map((m: any) => m.id)).toEqual([a.id]);
  });
});
