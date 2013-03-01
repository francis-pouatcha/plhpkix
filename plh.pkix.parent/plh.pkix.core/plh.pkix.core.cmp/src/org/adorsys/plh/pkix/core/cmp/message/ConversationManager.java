package org.adorsys.plh.pkix.core.cmp.message;

/**
 * Manages conversations with other parties. Each message sent to another party
 * is generally a conversation. If the message requires a response, the sent 
 * message will be held by the conversation manager till the response is received.
 * 
 * All requests are sent synchronously to the server. The server can decide either 
 * to reply right away or send a polling reply and keep the request for the destinator.
 * 
 * @author francis
 *
 */
public class ConversationManager {

}
