/*
 * AppFastLane.cpp
 *
 *  Created on: Aug. 16, 2019
 *      Author: rpb
 */

#include <boost/log/trivial.hpp>

#include <Wt/Chart/WCartesianChart.h>

#include "AppFastLane.h"

AppFastLane::AppFastLane( const Wt::WEnvironment& env )
: Wt::WApplication( env )
  ,m_environment( env )
  ,m_pServer( dynamic_cast<Server*>( env.server() ) )
  ,m_menuPersonal( nullptr )
  ,m_cwContent( nullptr )
  ,m_cwFooter( nullptr )
  ,m_cwStatus( nullptr )
  ,m_nRows {}
{
}

AppFastLane::~AppFastLane() { }

void AppFastLane::initialize() {

  BOOST_LOG_TRIVIAL(info) << sessionId() << ",initialize()";

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

  Wt::WContainerWidget* pContainer = root()->addWidget( std::make_unique<Wt::WContainerWidget>() );

  m_pModel = std::make_shared<Model1>();
  //m_pModel = std::make_shared<Wt::WStandardItemModel>(0, 4);
  m_pModel->setHeaderData( 0, Wt::WString("Time") );
  m_pModel->setHeaderData( 1, Wt::WString("TCP") );
  m_pModel->setHeaderData( 2, Wt::WString("UDP") );
  m_pModel->setHeaderData( 3, Wt::WString("ICMP") );

  m_pServer->m_signalStats.connect( this, &AppFastLane::UpdateModel );

  Wt::Chart::WCartesianChart* pChart = pContainer->addWidget( std::make_unique<Wt::Chart::WCartesianChart>() );

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

  std::unique_ptr<Wt::Chart::WDataSeries> pTcp = std::make_unique<Wt::Chart::WDataSeries>( 1, Wt::Chart::SeriesType::Point );
  pChart->addSeries( std::move( pTcp ) );

  std::unique_ptr<Wt::Chart::WDataSeries> pUdp = std::make_unique<Wt::Chart::WDataSeries>( 2, Wt::Chart::SeriesType::Point );
  pChart->addSeries( std::move( pUdp ) );

  std::unique_ptr<Wt::Chart::WDataSeries> pIcmp = std::make_unique<Wt::Chart::WDataSeries>( 3, Wt::Chart::SeriesType::Point );
  pChart->addSeries( std::move( pIcmp ) );


}

void AppFastLane::UpdateModel( Wt::WDateTime dt, long long tcp, long long udp, long long icmp ) {
  m_pServer->post(
    sessionId(),
    [this,dt, tcp, udp, icmp](){
      m_pModel->insertRow( m_nRows );

      m_pModel->setData( m_pModel->index( m_nRows, 0 ), std::any( dt ) );
      m_pModel->setData( m_pModel->index( m_nRows, 1 ), std::any( tcp ) );
      m_pModel->setData( m_pModel->index( m_nRows, 2 ), std::any( udp ) );
      m_pModel->setData( m_pModel->index( m_nRows, 3 ), std::any( icmp ) );
      m_nRows++;
    });
}
