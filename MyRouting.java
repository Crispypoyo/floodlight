/*******************

Team members and IDs:
Joseph Bermudez 6052768

Github link:
https://github.com/Crispypoyo/floodlight

*******************/

package net.floodlightcontroller.myrouting;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.HashSet;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;

import java.util.ArrayList;
import java.util.Set;

import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RouteId;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.NodePortTuple;

import org.openflow.util.HexString;
import org.openflow.util.U8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyRouting implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected IDeviceService deviceProvider;
	protected ILinkDiscoveryService linkProvider;

	protected Map<Long, IOFSwitch> switches;
	protected Map<Link, LinkInfo> links;
	protected Collection<? extends IDevice> devices;

	protected static int uniqueFlow;
	protected ILinkDiscoveryService lds;
	protected IStaticFlowEntryPusherService flowPusher;
	protected boolean printedTopo = false;

	@Override
	public String getName() {
		return MyRouting.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN)
				&& (name.equals("devicemanager") || name.equals("topology")) || name
					.equals("forwarding"));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(ILinkDiscoveryService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		deviceProvider = context.getServiceImpl(IDeviceService.class);
		linkProvider = context.getServiceImpl(ILinkDiscoveryService.class);
		flowPusher = context
				.getServiceImpl(IStaticFlowEntryPusherService.class);
		lds = context.getServiceImpl(ILinkDiscoveryService.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx)
	{


		// Print the topology if not yet.
		if (!printedTopo) {
			System.out.println("*** Print topology");

			// For each switch, print its neighbor switches.
			links = new HashMap<>(lds.getLinks());
			Map<Long, Set<Link>> listOfSwitches = lds.getSwitchLinks();
			
			for(Map.Entry<Long, Set<Link>> starter : listOfSwitches.entrySet())
			{
				System.out.print("switch " + starter.getKey() + " neighbors: ");
				HashSet<Long> linkIDs = new HashSet<Long>();
				for(Link link : starter.getValue())
				{
					if(starter.getKey() == link.getDst())
					{
						linkIDs.add(link.getSrc());
					}
					else
					{
						linkIDs.add(link.getDst());
					}
				}
				boolean first = true;
				for(Long id : linkIDs)
				{
					if(first)
					{
						System.out.print(id);
						first = false;
						
					}
					else
					{
						System.out.print(", " + id);
					}
				}
				System.out.println();
			}

			printedTopo = true;
		}


		// eth is the packet sent by a switch and received by floodlight.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		// We process only IP packets of type 0x0800.
		if (eth.getEtherType() != 0x0800) {
			return Command.CONTINUE;
		}
		else
		{
			System.out.println("*** New flow packet");

			// Parse the incoming packet.
			OFPacketIn pi = (OFPacketIn)msg;
			OFMatch match = new OFMatch();
		    match.loadFromPacket(pi.getPacketData(), pi.getInPort());	
			
			// Obtain source and destination IPs.
			// ...
			System.out.println("srcIP: " + match.getNetworkSourceCIDR());
	        System.out.println("dstIP: " + match.getNetworkDestinationCIDR());


			// Calculate the path using Dijkstra's algorithm.
			Route route = null;
			Map<Long, Set<Link>> switchIDs = lds.getSwitchLinks();
			
			if(!switchIDs.isEmpty())
			{
				Set<Long> visitedNode = new HashSet<>();
				ArrayList<Long> nextNode = new ArrayList<Long>();
				Map<Long, Integer> distanceFromSrc = new HashMap<>();
				Map<Long, Long> parentNode = new HashMap<>();
				
				for(Map.Entry<Long, Set<Link>> start: switchIDs.entrySet())
				{
					distanceFromSrc.put(start.getKey(), Integer.MAX_VALUE); //Max value to replicate infinity
					parentNode.put(start.getKey(), start.getKey());
				}
				
				Long sourceID = eth.getSourceMAC().toLong();
				
				distanceFromSrc.put(sourceID, 0);
				nextNode.add(sourceID);
				
				while(!nextNode.isEmpty())
				{
					if(!visitedNode.contains(nextNode.get(0)))
					{
						Long nodeID = nextNode.get(0);
						Set<Link> neighborNode = switchIDs.get(nodeID);
						for(Link neighbors: neighborNode)
						{
							if(neighbors.getSrc() == nodeID)
							{
								if(!visitedNode.contains(neighbors.getDst()))
								{
									nextNode.add(neighbors.getDst());
									int cost = 10 + distanceFromSrc.get(nodeID);
									if(nodeID % 2 == 0 && neighbors.getDst() % 2 == 0)
									{
										cost = 100 + distanceFromSrc.get(nodeID);
									}
									else if(nodeID % 2 != 0 && neighbors.getDst() % 2 != 0)
									{
										cost = 1 + distanceFromSrc.get(nodeID);
									}
									int currentCost = distanceFromSrc.get(neighbors.getDst());
									if(cost < currentCost)
									{
										parentNode.put(neighbors.getDst(), nodeID);
										distanceFromSrc.put(neighbors.getDst(), cost);
									}
								}
							}
						}
						visitedNode.add(nodeID);
						nextNode.remove(0);
					}
					else
					{
						nextNode.remove(0);
					}
				}
				List<Long> printingRoute = new ArrayList<Long>();
				Boolean bool = true;
				Long next = eth.getDestinationMAC().toLong();
				while(bool)
				{
					printingRoute.add(next);
					if(parentNode.get(next) == next)
					{
						bool = false;
					}
					else
					{
						next = parentNode.get(next);
					}
				}
				List<Long> reversed = new ArrayList<Long>();
				System.out.print("route:");
				for(int i = printingRoute.size() - 1; i >= 0; i--)
				{
					reversed.add(printingRoute.get(i));
					System.out.print(" " + printingRoute.get(i));
				}
			}
				if (route != null)
				{
					installRoute(route.getPath(), match);
				}
				
				return Command.STOP;
		}
	}

	// Install routing rules on switches. 
	private void installRoute(List<NodePortTuple> path, OFMatch match) {

		OFMatch m = new OFMatch();

		m.setDataLayerType(Ethernet.TYPE_IPv4)
				.setNetworkSource(match.getNetworkSource())
				.setNetworkDestination(match.getNetworkDestination());

		for (int i = 0; i <= path.size() - 1; i += 2) {
			short inport = path.get(i).getPortId();
			m.setInputPort(inport);
			List<OFAction> actions = new ArrayList<OFAction>();
			OFActionOutput outport = new OFActionOutput(path.get(i + 1)
					.getPortId());
			actions.add(outport);

			OFFlowMod mod = (OFFlowMod) floodlightProvider
					.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
			mod.setCommand(OFFlowMod.OFPFC_ADD)
					.setIdleTimeout((short) 0)
					.setHardTimeout((short) 0)
					.setMatch(m)
					.setPriority((short) 105)
					.setActions(actions)
					.setLength(
							(short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
			flowPusher.addFlow("routeFlow" + uniqueFlow, mod,
					HexString.toHexString(path.get(i).getNodeId()));
			uniqueFlow++;
		}
	}
}
