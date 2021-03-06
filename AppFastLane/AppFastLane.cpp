/*
 * AppFastLane.cpp
 *
 *  Created on: Aug. 16, 2019
 *      Author: rpb
 */

#include <boost/log/trivial.hpp>

#include <Wt/Chart/WCartesianChart.h>
#include <Wt/WText.h>

#include "AppFastLane.h"

AppFastLane::AppFastLane( const Wt::WEnvironment& env )
: Wt::WApplication( env )
  ,m_environment( env )
  ,m_pServer( dynamic_cast<Server*>( env.server() ) )
  ,m_menuPersonal( nullptr )
  ,m_cwContent( nullptr )
  ,m_cwFooter( nullptr )
  ,m_cwStatus( nullptr )
  ,m_bAbsoluteSet( false )
  ,m_nRows {}
{
}

AppFastLane::~AppFastLane() { }

void AppFastLane::initialize() {

  BOOST_LOG_TRIVIAL(info) << sessionId() << ",initialize()";

  enableUpdates( true );

  BuildInitialPage();

}

void AppFastLane::finalize() {
  BOOST_LOG_TRIVIAL(info) << sessionId() << ",finalize()";
  // TOOD: save time/date of last interaction?  or do on each page request?
  //SessionClose();
}

void AppFastLane::BuildInitialPage() {

  setCssTheme("polished");
  //useStyleSheet("resources/themes/bootstrap/3/less/normalize.less" ); // loaded automatically by bootstrap.css
  //useStyleSheet("resources/themes/bootstrap/3/less/navs.less" );
  //useStyleSheet("resources/themes/bootstrap/3/less/dropdowns.less" );
  useStyleSheet("resources/themes/bootstrap/3/bootstrap.css");
  useStyleSheet("resources/themes/bootstrap/3/wt.css");
  useStyleSheet("style/ounl.css");

  root()->clear();

  // ==== container: main
  Wt::WContainerWidget* pContainerMain = root()->addWidget(std::make_unique<Wt::WContainerWidget>() );

  // ==== container : row 1 with interface list and chart
  Wt::WContainerWidget* pContainerRow1 = pContainerMain->addWidget( std::make_unique<Wt::WContainerWidget>() );
  pContainerRow1->setStyleClass("classInterfaceGroup" );

  // ==== container: interface list
  Wt::WContainerWidget* pContainerInterfaceList = pContainerRow1->addWidget(std::make_unique<Wt::WContainerWidget>() );
  pContainerInterfaceList->setStyleClass( "classInterfaceList" );
  m_pServer->GetInterfaceList( // call into WServer, but comes back in different thread
    [this,pContainerInterfaceList](int if_index,const std::string& sInterfaceName){ // process each interface index and name
      m_pServer->post( // WServer space into WApplication space
        sessionId(),
        [this,pContainerInterfaceList,if_index,sInterfaceName_=sInterfaceName](){
          Wt::WContainerWidget* pContainerInterfaceItem = pContainerInterfaceList->addWidget( std::make_unique<Wt::WContainerWidget>() );
          pContainerInterfaceItem->setStyleClass( "classInterfaceItem" );
          Wt::WText* pInterfaceName = pContainerInterfaceItem->addWidget( std::make_unique<Wt::WText>( sInterfaceName_ ) );
          pInterfaceName->setStyleClass( "classInterfaceName" );
          pInterfaceName->clicked().connect(
            [this,if_index](){ // on clicked, in WApplication
              BOOST_LOG_TRIVIAL(info) << sessionId() << ",if_index clicked=" << if_index;
              if ( m_connectionStats64.connected() ) m_connectionStats64.disconnect();
              m_bAbsoluteSet = false;
              m_nRows = 0;
              m_pModel->removeRows( 0, m_pModel->rowCount() );
              m_pServer->InterfaceStats64( // call into WServer, but comes back in different thread
                if_index,
                [this](const rtnl_link_stats64& stats){ // WServer threading into WApplication space
                  m_pServer->post( // pass from WServer into WApplication
                    sessionId(),
                    [this,stats](){ // in WApplication space:
                      if ( m_bAbsoluteSet ) {
                        m_pModel->insertRow( m_nRows );
                        m_pModel->setData( m_pModel->index( m_nRows, 0 ), std::any( Wt::WDateTime::currentDateTime() ) );
                        m_pModel->setData( m_pModel->index( m_nRows, 1 ), std::any( (long long)( stats.rx_packets - m_rx_packets ) ) );
                        m_pModel->setData( m_pModel->index( m_nRows, 2 ), std::any( (long long)( stats.tx_packets - m_tx_packets ) ) );
                        m_pModel->setData( m_pModel->index( m_nRows, 3 ), std::any( (long long)( stats.collisions - m_collisions ) ) );
                        m_rx_packets = stats.rx_packets;
                        m_tx_packets = stats.tx_packets;
                        m_collisions = stats.collisions;
                        m_nRows++;
                        triggerUpdate();
                      }
                      else {
                        m_rx_packets = stats.rx_packets;
                        m_tx_packets = stats.tx_packets;
                        m_collisions = stats.collisions;
                        m_bAbsoluteSet = true;
                      }
                    }
                    );
                },
                [this](boost::signals2::connection connection){
                  m_connectionStats64 = connection;
                } );
            });
        }
        );
    }
    );

  // ==== container: chart
  Wt::Chart::WCartesianChart* pChart = pContainerRow1->addWidget(std::make_unique<Wt::Chart::WCartesianChart>() );
  pChart->setStyleClass( "classInterfaceChart" );

  m_pModel = std::make_shared<Model1>();
  //m_pModel = std::make_shared<Wt::WStandardItemModel>(0, 4);
  m_pModel->setHeaderData( 0, Wt::Orientation::Horizontal, Wt::WString("Time"), Wt::ItemDataRole::Display );
  m_pModel->setHeaderData( 1, Wt::Orientation::Horizontal, Wt::WString("rx packets"), Wt::ItemDataRole::Display );
  m_pModel->setHeaderData( 2, Wt::Orientation::Horizontal, Wt::WString("tx packets"), Wt::ItemDataRole::Display );
  m_pModel->setHeaderData( 3, Wt::Orientation::Horizontal, Wt::WString("collisions"), Wt::ItemDataRole::Display );

  m_pServer->m_signalStats.connect( this, &AppFastLane::UpdateModel );

  pChart->setModel( m_pModel );
  pChart->setType( Wt::Chart::ChartType::Scatter );
  pChart->setXSeriesColumn( 0 );
  pChart->axis( Wt::Chart::Axis::X ).setScale( Wt::Chart::AxisScale::DateTime );
  pChart->setLegendEnabled(true);
  pChart->setBackground( Wt::WColor( 220, 220, 220 ) );
  pChart->setAutoLayoutEnabled();
  pChart->setPlotAreaPadding( 40, Wt::Side::Left | Wt::Side::Top | Wt::Side::Bottom );
  pChart->setPlotAreaPadding( 120, Wt::Side::Right );
  pChart->resize( 800, 400 );
  pChart->setMargin( Wt::WLength::Auto, Wt::Side::Left | Wt::Side::Right );

  std::unique_ptr<Wt::Chart::WDataSeries> pTcp = std::make_unique<Wt::Chart::WDataSeries>( 1, Wt::Chart::SeriesType::Line );
  pChart->addSeries( std::move( pTcp ) );

  std::unique_ptr<Wt::Chart::WDataSeries> pUdp = std::make_unique<Wt::Chart::WDataSeries>( 2, Wt::Chart::SeriesType::Line );
  pChart->addSeries( std::move( pUdp ) );

  std::unique_ptr<Wt::Chart::WDataSeries> pIcmp = std::make_unique<Wt::Chart::WDataSeries>( 3, Wt::Chart::SeriesType::Line );
  pChart->addSeries( std::move( pIcmp ) );

  // ==== container row 2
  Wt::WContainerWidget* pContainerRow2 = pContainerMain->addWidget( std::make_unique<Wt::WContainerWidget>() );

  // ==== container mac address list and statistics:
  Wt::WContainerWidget* pContainerMacList = pContainerRow2->addWidget( std::make_unique<Wt::WContainerWidget>() );

  // ==== container ipv4 address list and statistics:
  Wt::WContainerWidget* pContainerIpv4List = pContainerRow2->addWidget( std::make_unique<Wt::WContainerWidget>() );

  // ==== container ipv6 address list and statistics:
  Wt::WContainerWidget* pContainerIpv6List = pContainerRow2->addWidget( std::make_unique<Wt::WContainerWidget>() );
}

void AppFastLane::UpdateModel( Wt::WDateTime dt, long long tcp, long long udp, long long icmp ) {
  /*
  m_pServer->post(
    sessionId(),
    [this,dt, tcp, udp, icmp](){
      m_pModel->insertRow( m_nRows );

      m_pModel->setData( m_pModel->index( m_nRows, 0 ), std::any( dt ) );
      m_pModel->setData( m_pModel->index( m_nRows, 1 ), std::any( tcp ) );
      m_pModel->setData( m_pModel->index( m_nRows, 2 ), std::any( udp ) );
      m_pModel->setData( m_pModel->index( m_nRows, 3 ), std::any( icmp ) );
      m_nRows++;
      triggerUpdate();
    });
    */
}
