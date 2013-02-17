package plh.pkix.client.messaging.mail.sender;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingDeque;

/**
 * Manages interaction with email servers asynchronously.
 * 
 * The TaskSource is an executor that receives the email task from the messaging service and
 * puts it in an order queue. This blocking queue which is consumes at the other end by the
 * task processor.
 * 
 * The task processor has a thread pool and all it's thread block read on the order queue,
 * waiting for orders. Each email task will be sent to the email server and the result will
 * be put into a result queue.
 * 
 * The email task result is also a runnable. This result is put by the processor thread into
 * the result queue. This is also a blocking queue.
 * 
 *  At the other end of the result queue, the result handler reads available results and
 *  execute them.
 * 
 * @author francis
 *
 */
public class EmailTaskManager {

	private ExecutorService taskSource = Executors.newFixedThreadPool(5);
	
	private BlockingQueue<EmailTask> emailTaskQueue = new LinkedBlockingDeque<EmailTask>(20);
	
}
