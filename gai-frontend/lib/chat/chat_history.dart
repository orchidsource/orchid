import 'package:orchid/orchid/orchid.dart';
import 'package:orchid/chat/chat_message.dart';

/// Manages chat history and prepares messages for model inference requests.
/// Supports different modes of history preparation and will eventually support
/// user-supplied preparation scripts.
class ChatHistory {
  final List<ChatMessage> _messages = [];

  // Built-in preparation functions
  static const String isolatedMode = 'isolated';
  static const String partyMode = 'party-mode';

  void addMessage(ChatMessage message) {
    _messages.add(message);
  }

  List<ChatMessage> get messages => List.unmodifiable(_messages);

  void clear() {
    _messages.clear();
  }

  // Return the client and provider messages, optionally limited to the specified model id.
  // System and internal messages are always excluded.
  List<ChatMessage> getConversation({String? withModelId}) {
    return _messages
        .where((msg) =>
            // Only include client messages and this model's responses
            (msg.source == ChatMessageSource.client) ||
            (msg.source == ChatMessageSource.provider &&
                (withModelId == null || msg.modelId == withModelId)))
        .toList();
  }
}
